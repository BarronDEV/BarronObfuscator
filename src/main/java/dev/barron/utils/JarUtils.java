package dev.barron.utils;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

/**
 * Utilities for reading and writing JAR files
 */
public class JarUtils {

    /**
     * Read all entries from a JAR file
     */
    public static Map<String, byte[]> readJar(Path jarPath) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();

        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> jarEntries = jar.entries();

            while (jarEntries.hasMoreElements()) {
                JarEntry entry = jarEntries.nextElement();

                if (!entry.isDirectory()) {
                    try (InputStream is = jar.getInputStream(entry)) {
                        entries.put(entry.getName(), is.readAllBytes());
                    }
                }
            }
        }

        return entries;
    }

    /**
     * Write entries to a JAR file
     */
    public static void writeJar(Path jarPath, Map<String, byte[]> entries) throws IOException {
        writeJar(jarPath, entries, null);
    }

    /**
     * Write entries to a JAR file with manifest
     */
    public static void writeJar(Path jarPath, Map<String, byte[]> entries, Manifest manifest) throws IOException {
        try (JarOutputStream jos = manifest != null
                ? new JarOutputStream(new FileOutputStream(jarPath.toFile()), manifest)
                : new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {

            Set<String> writtenDirs = new HashSet<>();

            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();

                // Skip manifest if we're writing our own
                if (manifest != null && name.equals("META-INF/MANIFEST.MF")) {
                    continue;
                }

                // Create parent directories
                createParentDirs(jos, name, writtenDirs);

                // Write the entry
                JarEntry jarEntry = new JarEntry(name);
                jos.putNextEntry(jarEntry);
                jos.write(entry.getValue());
                jos.closeEntry();
            }
        }
    }

    private static void createParentDirs(JarOutputStream jos, String name, Set<String> writtenDirs) throws IOException {
        String[] parts = name.split("/");
        StringBuilder path = new StringBuilder();

        for (int i = 0; i < parts.length - 1; i++) {
            path.append(parts[i]).append("/");
            String dirPath = path.toString();

            if (!writtenDirs.contains(dirPath)) {
                JarEntry dirEntry = new JarEntry(dirPath);
                jos.putNextEntry(dirEntry);
                jos.closeEntry();
                writtenDirs.add(dirPath);
            }
        }
    }

    /**
     * Extract manifest from JAR entries
     */
    public static Manifest extractManifest(Map<String, byte[]> entries) throws IOException {
        byte[] manifestBytes = entries.get("META-INF/MANIFEST.MF");

        if (manifestBytes != null) {
            return new Manifest(new ByteArrayInputStream(manifestBytes));
        }

        return new Manifest();
    }

    /**
     * Get all class entries from JAR
     */
    public static Map<String, byte[]> getClassEntries(Map<String, byte[]> entries) {
        Map<String, byte[]> classes = new LinkedHashMap<>();

        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            if (entry.getKey().endsWith(".class")) {
                classes.put(entry.getKey(), entry.getValue());
            }
        }

        return classes;
    }

    /**
     * Get all resource (non-class) entries from JAR
     */
    public static Map<String, byte[]> getResourceEntries(Map<String, byte[]> entries) {
        Map<String, byte[]> resources = new LinkedHashMap<>();

        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            if (!entry.getKey().endsWith(".class")) {
                resources.put(entry.getKey(), entry.getValue());
            }
        }

        return resources;
    }

    /**
     * Convert class file path to class name
     * e.g., "com/example/MyClass.class" -> "com.example.MyClass"
     */
    public static String pathToClassName(String path) {
        return path.replace("/", ".").replace(".class", "");
    }

    /**
     * Convert class name to class file path
     * e.g., "com.example.MyClass" -> "com/example/MyClass.class"
     */
    public static String classNameToPath(String className) {
        return className.replace(".", "/") + ".class";
    }

    /**
     * Convert internal name to class name
     * e.g., "com/example/MyClass" -> "com.example.MyClass"
     */
    public static String internalToClassName(String internalName) {
        return internalName.replace("/", ".");
    }

    /**
     * Convert class name to internal name
     * e.g., "com.example.MyClass" -> "com/example/MyClass"
     */
    public static String classNameToInternal(String className) {
        return className.replace(".", "/");
    }
}
