package dev.barron.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Generates mapping files for de-obfuscation of stack traces
 * Compatible with ProGuard format for tool compatibility
 */
public class MappingGenerator {

    private final Map<String, String> classMap = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> methodMap = new LinkedHashMap<>(); // className -> (oldMethod ->
                                                                                      // newMethod)
    private final Map<String, Map<String, String>> fieldMap = new LinkedHashMap<>(); // className -> (oldField ->
                                                                                     // newField)

    private String inputFileName;
    private String outputFileName;

    public void setFileNames(String input, String output) {
        this.inputFileName = input;
        this.outputFileName = output;
    }

    /**
     * Record a class mapping
     */
    public void addClass(String originalName, String obfuscatedName) {
        classMap.put(originalName, obfuscatedName);
    }

    /**
     * Record a method mapping
     */
    public void addMethod(String className, String originalMethod, String descriptor, String obfuscatedMethod) {
        methodMap.computeIfAbsent(className, k -> new LinkedHashMap<>())
                .put(originalMethod + descriptor, obfuscatedMethod);
    }

    /**
     * Record a field mapping
     */
    public void addField(String className, String originalField, String obfuscatedField) {
        fieldMap.computeIfAbsent(className, k -> new LinkedHashMap<>())
                .put(originalField, obfuscatedField);
    }

    /**
     * Write mapping file in ProGuard-compatible format
     */
    public void writeProGuardFormat(Path outputPath) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            // Header
            writer.write("# Barron Obfuscator Mapping File\n");
            writer.write("# Generated: " + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "\n");
            if (inputFileName != null) {
                writer.write("# Input: " + inputFileName + "\n");
            }
            if (outputFileName != null) {
                writer.write("# Output: " + outputFileName + "\n");
            }
            writer.write("#\n");
            writer.write("# Format: ProGuard compatible\n");
            writer.write("# Use this file to de-obfuscate stack traces\n");
            writer.write("#\n\n");

            // Write class mappings
            for (Map.Entry<String, String> entry : classMap.entrySet()) {
                String originalClass = entry.getKey().replace("/", ".");
                String obfuscatedClass = entry.getValue().replace("/", ".");

                writer.write(originalClass + " -> " + obfuscatedClass + ":\n");

                // Write field mappings for this class
                Map<String, String> fields = fieldMap.get(entry.getKey());
                if (fields != null) {
                    for (Map.Entry<String, String> fieldEntry : fields.entrySet()) {
                        writer.write("    " + fieldEntry.getKey() + " -> " + fieldEntry.getValue() + "\n");
                    }
                }

                // Write method mappings for this class
                Map<String, String> methods = methodMap.get(entry.getKey());
                if (methods != null) {
                    for (Map.Entry<String, String> methodEntry : methods.entrySet()) {
                        String originalMethod = methodEntry.getKey();
                        String obfuscatedMethod = methodEntry.getValue();

                        // Parse method name and descriptor
                        int descStart = originalMethod.indexOf('(');
                        String methodName = descStart > 0 ? originalMethod.substring(0, descStart) : originalMethod;
                        String descriptor = descStart > 0 ? originalMethod.substring(descStart) : "";

                        writer.write("    " + formatDescriptor(descriptor) + " " + methodName +
                                formatMethodArgs(descriptor) + " -> " + obfuscatedMethod + "\n");
                    }
                }
            }
        }
    }

    /**
     * Write mapping in JSON format (easier for custom tools)
     */
    public void writeJsonFormat(Path outputPath) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            writer.write("{\n");
            writer.write("  \"generated\": \"" + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    + "\",\n");
            writer.write("  \"input\": \"" + (inputFileName != null ? inputFileName : "") + "\",\n");
            writer.write("  \"output\": \"" + (outputFileName != null ? outputFileName : "") + "\",\n");
            writer.write("  \"classes\": {\n");

            Iterator<Map.Entry<String, String>> classIt = classMap.entrySet().iterator();
            while (classIt.hasNext()) {
                Map.Entry<String, String> entry = classIt.next();
                String originalClass = entry.getKey().replace("/", ".");
                String obfuscatedClass = entry.getValue().replace("/", ".");

                writer.write("    \"" + originalClass + "\": {\n");
                writer.write("      \"name\": \"" + obfuscatedClass + "\"");

                // Fields
                Map<String, String> fields = fieldMap.get(entry.getKey());
                if (fields != null && !fields.isEmpty()) {
                    writer.write(",\n      \"fields\": {\n");
                    Iterator<Map.Entry<String, String>> fieldIt = fields.entrySet().iterator();
                    while (fieldIt.hasNext()) {
                        Map.Entry<String, String> fieldEntry = fieldIt.next();
                        writer.write("        \"" + fieldEntry.getKey() + "\": \"" + fieldEntry.getValue() + "\"");
                        writer.write(fieldIt.hasNext() ? ",\n" : "\n");
                    }
                    writer.write("      }");
                }

                // Methods
                Map<String, String> methods = methodMap.get(entry.getKey());
                if (methods != null && !methods.isEmpty()) {
                    writer.write(",\n      \"methods\": {\n");
                    Iterator<Map.Entry<String, String>> methodIt = methods.entrySet().iterator();
                    while (methodIt.hasNext()) {
                        Map.Entry<String, String> methodEntry = methodIt.next();
                        writer.write("        \"" + escapeJson(methodEntry.getKey()) + "\": \"" + methodEntry.getValue()
                                + "\"");
                        writer.write(methodIt.hasNext() ? ",\n" : "\n");
                    }
                    writer.write("      }");
                }

                writer.write("\n    }");
                writer.write(classIt.hasNext() ? ",\n" : "\n");
            }

            writer.write("  }\n");
            writer.write("}\n");
        }
    }

    /**
     * Format a JVM descriptor return type
     */
    private String formatDescriptor(String descriptor) {
        if (descriptor.isEmpty())
            return "void";

        int retStart = descriptor.lastIndexOf(')') + 1;
        if (retStart <= 0 || retStart >= descriptor.length())
            return "void";

        return formatType(descriptor.substring(retStart));
    }

    /**
     * Format method arguments from descriptor
     */
    private String formatMethodArgs(String descriptor) {
        if (descriptor.isEmpty())
            return "()";

        int start = descriptor.indexOf('(');
        int end = descriptor.indexOf(')');
        if (start < 0 || end < 0)
            return "()";

        String args = descriptor.substring(start + 1, end);
        if (args.isEmpty())
            return "()";

        StringBuilder sb = new StringBuilder("(");
        int i = 0;
        boolean first = true;
        while (i < args.length()) {
            if (!first)
                sb.append(",");
            first = false;

            char c = args.charAt(i);
            if (c == 'L') {
                int semicolon = args.indexOf(';', i);
                sb.append(args.substring(i + 1, semicolon).replace("/", "."));
                i = semicolon + 1;
            } else if (c == '[') {
                int arrayDepth = 0;
                while (i < args.length() && args.charAt(i) == '[') {
                    arrayDepth++;
                    i++;
                }
                if (i < args.length()) {
                    char elemType = args.charAt(i);
                    if (elemType == 'L') {
                        int semicolon = args.indexOf(';', i);
                        sb.append(args.substring(i + 1, semicolon).replace("/", "."));
                        i = semicolon + 1;
                    } else {
                        sb.append(formatPrimitive(elemType));
                        i++;
                    }
                }
                sb.append("[]".repeat(arrayDepth));
            } else {
                sb.append(formatPrimitive(c));
                i++;
            }
        }
        sb.append(")");
        return sb.toString();
    }

    private String formatType(String type) {
        if (type.isEmpty())
            return "void";

        char c = type.charAt(0);
        if (c == 'L') {
            return type.substring(1, type.length() - 1).replace("/", ".");
        } else if (c == '[') {
            return formatType(type.substring(1)) + "[]";
        } else {
            return formatPrimitive(c);
        }
    }

    private String formatPrimitive(char c) {
        return switch (c) {
            case 'B' -> "byte";
            case 'C' -> "char";
            case 'D' -> "double";
            case 'F' -> "float";
            case 'I' -> "int";
            case 'J' -> "long";
            case 'S' -> "short";
            case 'Z' -> "boolean";
            case 'V' -> "void";
            default -> String.valueOf(c);
        };
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * Get statistics
     */
    public int getClassCount() {
        return classMap.size();
    }

    public int getMethodCount() {
        return methodMap.values().stream().mapToInt(Map::size).sum();
    }

    public int getFieldCount() {
        return fieldMap.values().stream().mapToInt(Map::size).sum();
    }
}
