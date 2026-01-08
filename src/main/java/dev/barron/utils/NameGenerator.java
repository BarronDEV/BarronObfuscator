package dev.barron.utils;

import java.security.SecureRandom;
import java.util.*;

/**
 * Generates obfuscated names for classes, methods, and fields
 * Uses random seed per session for unique naming
 */
public class NameGenerator {

    private final SecureRandom random;
    private final Map<String, String> mappings = new HashMap<>();
    private final Set<String> usedNames = new HashSet<>();

    // Different naming styles
    public enum Style {
        ALPHABET, // a, b, c, aa, ab...
        UNICODE, // Uses similar-looking unicode chars
        ILLEGIBLE, // Il1O0 combinations
        RANDOM // Random alphanumeric
    }

    private Style style = Style.ALPHABET;
    private int counter = 0;

    // Characters for different styles
    private static final String ALPHABET_CHARS = "abcdefghijklmnopqrstuvwxyz";
    private static final String ILLEGIBLE_CHARS = "IlO0";
    private static final String RANDOM_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Unicode characters that look similar to latin letters
    private static final String[] UNICODE_ALTERNATIVES = {
            "а", "b", "с", "d", "е", "f", "g", "h", "і", "j", "k", "l", "m",
            "n", "о", "р", "q", "r", "ѕ", "t", "u", "v", "w", "x", "у", "z"
    };

    public NameGenerator() {
        this.random = new SecureRandom();
    }

    public NameGenerator(long seed) {
        this.random = new SecureRandom();
        this.random.setSeed(seed);
    }

    public void setStyle(Style style) {
        this.style = style;
    }

    /**
     * Generate a new unique name for an identifier
     */
    public String generateName(String original) {
        if (mappings.containsKey(original)) {
            return mappings.get(original);
        }

        String newName;
        do {
            newName = generateUniqueName();
        } while (usedNames.contains(newName) || isReservedWord(newName));

        usedNames.add(newName);
        mappings.put(original, newName);
        return newName;
    }

    /**
     * Generate a unique class name (must be valid Java identifier)
     */
    public String generateClassName(String original) {
        if (mappings.containsKey(original)) {
            return mappings.get(original);
        }

        String newName;
        do {
            newName = generateUniqueName();
            // Ensure it starts with uppercase for class convention
            if (!newName.isEmpty()) {
                newName = Character.toUpperCase(newName.charAt(0)) +
                        (newName.length() > 1 ? newName.substring(1) : "");
            }
        } while (usedNames.contains(newName) || isReservedWord(newName));

        usedNames.add(newName);
        mappings.put(original, newName);
        return newName;
    }

    /**
     * Generate a package path (a/b/c style)
     */
    public String generatePackagePath(String original) {
        String key = "pkg:" + original;
        if (mappings.containsKey(key)) {
            return mappings.get(key);
        }

        // Generate short package like "a/a" or "a/b/c"
        StringBuilder sb = new StringBuilder();
        int depth = random.nextInt(2) + 1; // 1-2 depth
        for (int i = 0; i <= depth; i++) {
            if (i > 0)
                sb.append("/");
            sb.append((char) ('a' + random.nextInt(3)));
        }

        String newName = sb.toString();
        mappings.put(key, newName);
        return newName;
    }

    private String generateUniqueName() {
        return switch (style) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName();
            case ILLEGIBLE -> generateIllegibleName();
            case RANDOM -> generateRandomName();
        };
    }

    private String generateAlphabetName() {
        int n = counter++;
        StringBuilder sb = new StringBuilder();

        do {
            sb.insert(0, ALPHABET_CHARS.charAt(n % 26));
            n = n / 26 - 1;
        } while (n >= 0);

        return sb.toString();
    }

    private String generateUnicodeName() {
        int length = random.nextInt(3) + 2; // 2-4 chars
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i++) {
            sb.append(UNICODE_ALTERNATIVES[random.nextInt(UNICODE_ALTERNATIVES.length)]);
        }

        return sb.toString();
    }

    private String generateIllegibleName() {
        int length = random.nextInt(6) + 4; // 4-9 chars
        StringBuilder sb = new StringBuilder();

        // Must start with I or l (valid identifier start)
        sb.append(random.nextBoolean() ? 'I' : 'l');

        for (int i = 1; i < length; i++) {
            sb.append(ILLEGIBLE_CHARS.charAt(random.nextInt(ILLEGIBLE_CHARS.length())));
        }

        return sb.toString();
    }

    private String generateRandomName() {
        int length = random.nextInt(4) + 2; // 2-5 chars
        StringBuilder sb = new StringBuilder();

        // First char must be letter
        sb.append(RANDOM_CHARS.charAt(random.nextInt(RANDOM_CHARS.length())));

        for (int i = 1; i < length; i++) {
            sb.append(RANDOM_CHARS.charAt(random.nextInt(RANDOM_CHARS.length())));
        }

        return sb.toString();
    }

    private boolean isReservedWord(String name) {
        return Set.of(
                "abstract", "assert", "boolean", "break", "byte", "case", "catch",
                "char", "class", "const", "continue", "default", "do", "double",
                "else", "enum", "extends", "final", "finally", "float", "for",
                "goto", "if", "implements", "import", "instanceof", "int", "interface",
                "long", "native", "new", "null", "package", "private", "protected",
                "public", "return", "short", "static", "strictfp", "super", "switch",
                "synchronized", "this", "throw", "throws", "transient", "true", "try",
                "void", "volatile", "while", "false", "var", "yield", "record", "sealed").contains(name);
    }

    /**
     * Get all mappings (for logging/debugging)
     */
    public Map<String, String> getMappings() {
        return Collections.unmodifiableMap(mappings);
    }

    /**
     * Get mapping for a specific name
     */
    public String getMapping(String original) {
        return mappings.get(original);
    }

    /**
     * Check if a name has been mapped
     */
    public boolean hasMapping(String original) {
        return mappings.containsKey(original);
    }

    /**
     * Reset the generator
     */
    public void reset() {
        mappings.clear();
        usedNames.clear();
        counter = 0;
    }
}
