package dev.barron.utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Extreme Randomization Engine
 * 
 * Provides high-entropy randomization for obfuscation to ensure
 * each obfuscation run produces completely different output.
 * 
 * Even with the same input JAR, the output will be vastly different
 * each time, making pattern-based cracking nearly impossible.
 */
public class RandomizationEngine {

    private final SecureRandom secureRandom;
    private final long sessionId;

    // Pool of transformation strategies
    private final List<TransformStrategy> strategies;

    // Random ranges for various parameters
    private static final int MIN_DEAD_CODE_BLOCKS = 1;
    private static final int MAX_DEAD_CODE_BLOCKS = 15;

    private static final int MIN_FAKE_METHODS = 2;
    private static final int MAX_FAKE_METHODS = 10;

    private static final int MIN_OPAQUE_PREDICATES = 1;
    private static final int MAX_OPAQUE_PREDICATES = 8;

    private static final int MIN_XOR_LAYERS = 2;
    private static final int MAX_XOR_LAYERS = 7;

    private static final int MIN_TIMING_CHECKS = 1;
    private static final int MAX_TIMING_CHECKS = 5;

    public RandomizationEngine() {
        this.secureRandom = new SecureRandom();
        this.sessionId = secureRandom.nextLong();
        this.strategies = initializeStrategies();

        // Shuffle strategies for this session
        Collections.shuffle(strategies, secureRandom);
    }

    /**
     * Initialize available transformation strategies
     */
    private List<TransformStrategy> initializeStrategies() {
        List<TransformStrategy> list = new ArrayList<>();

        // String encryption strategies
        list.add(new TransformStrategy("XOR_MULTI", StrategyType.STRING_ENCRYPT));
        list.add(new TransformStrategy("AES_CHAIN", StrategyType.STRING_ENCRYPT));
        list.add(new TransformStrategy("SUBSTITUTION_ROTATE", StrategyType.STRING_ENCRYPT));
        list.add(new TransformStrategy("BASE64_XOR_MIX", StrategyType.STRING_ENCRYPT));
        list.add(new TransformStrategy("REVERSE_XOR", StrategyType.STRING_ENCRYPT));

        // Control flow strategies
        list.add(new TransformStrategy("SWITCH_TABLE", StrategyType.CONTROL_FLOW));
        list.add(new TransformStrategy("DISPATCHER", StrategyType.CONTROL_FLOW));
        list.add(new TransformStrategy("OPAQUE_MATH", StrategyType.CONTROL_FLOW));
        list.add(new TransformStrategy("FAKE_EXCEPTION", StrategyType.CONTROL_FLOW));
        list.add(new TransformStrategy("NESTED_LOOPS", StrategyType.CONTROL_FLOW));

        // Dead code strategies
        list.add(new TransformStrategy("MATH_GARBAGE", StrategyType.DEAD_CODE));
        list.add(new TransformStrategy("STRING_GARBAGE", StrategyType.DEAD_CODE));
        list.add(new TransformStrategy("ARRAY_GARBAGE", StrategyType.DEAD_CODE));
        list.add(new TransformStrategy("LOOP_GARBAGE", StrategyType.DEAD_CODE));
        list.add(new TransformStrategy("EXCEPTION_GARBAGE", StrategyType.DEAD_CODE));

        // Anti-debug strategies
        list.add(new TransformStrategy("TIMING_CHECK", StrategyType.ANTI_DEBUG));
        list.add(new TransformStrategy("THREAD_CHECK", StrategyType.ANTI_DEBUG));
        list.add(new TransformStrategy("STACK_CHECK", StrategyType.ANTI_DEBUG));
        list.add(new TransformStrategy("MEMORY_CHECK", StrategyType.ANTI_DEBUG));
        list.add(new TransformStrategy("CHECKSUM_CHECK", StrategyType.ANTI_DEBUG));

        return list;
    }

    /**
     * Get session-unique ID
     */
    public long getSessionId() {
        return sessionId;
    }

    /**
     * Get random integer in a wide range
     */
    public int getRandomInt(int min, int max) {
        return min + secureRandom.nextInt(max - min + 1);
    }

    /**
     * Get random number of dead code blocks (1-15)
     */
    public int getDeadCodeBlockCount() {
        return getRandomInt(MIN_DEAD_CODE_BLOCKS, MAX_DEAD_CODE_BLOCKS);
    }

    /**
     * Get random number of fake methods (2-10)
     */
    public int getFakeMethodCount() {
        return getRandomInt(MIN_FAKE_METHODS, MAX_FAKE_METHODS);
    }

    /**
     * Get random number of opaque predicates (1-8)
     */
    public int getOpaquePredicateCount() {
        return getRandomInt(MIN_OPAQUE_PREDICATES, MAX_OPAQUE_PREDICATES);
    }

    /**
     * Get random number of XOR layers (2-7)
     */
    public int getXorLayerCount() {
        return getRandomInt(MIN_XOR_LAYERS, MAX_XOR_LAYERS);
    }

    /**
     * Get random number of timing checks (1-5)
     */
    public int getTimingCheckCount() {
        return getRandomInt(MIN_TIMING_CHECKS, MAX_TIMING_CHECKS);
    }

    /**
     * Get random probability (0.0 - 1.0)
     */
    public double getRandomProbability() {
        return secureRandom.nextDouble();
    }

    /**
     * Check if should apply transformation based on random chance
     */
    public boolean shouldApply(double baseProbability) {
        // Add variance to the probability
        double variance = (secureRandom.nextDouble() - 0.5) * 0.3;
        double adjustedProbability = Math.max(0, Math.min(1, baseProbability + variance));
        return secureRandom.nextDouble() < adjustedProbability;
    }

    /**
     * Generate a random obfuscated name with varying length
     */
    public String generateRandomName() {
        // Choose random length between 1-6 characters
        int length = getRandomInt(1, 6);

        // Choose random character set for this name
        String[] charSets = {
                "Il1", // Confusing chars
                "O0", // More confusing
                "abcdefgh", // Normal lowercase
                "ABCDEFGH", // Normal uppercase
                "\u0430\u0435", // Cyrillic lookalikes (а, е)
                "\u03B1\u03B2", // Greek letters (α, β)
        };

        String charSet = charSets[secureRandom.nextInt(charSets.length)];

        StringBuilder sb = new StringBuilder();
        // First char must be a letter
        sb.append((char) ('a' + secureRandom.nextInt(26)));

        for (int i = 1; i < length; i++) {
            sb.append(charSet.charAt(secureRandom.nextInt(charSet.length())));
        }

        return sb.toString();
    }

    /**
     * Generate random magic numbers for opaque predicates
     */
    public long getRandomMagicNumber() {
        // Use wide range: -10^12 to 10^12
        long range = 1_000_000_000_000L;
        return (secureRandom.nextLong() % range);
    }

    /**
     * Generate random XOR key with varying complexity
     */
    public int[] generateRandomXorKey(int length) {
        int complexity = getRandomInt(1, 4);
        int[] key = new int[length];

        switch (complexity) {
            case 1 -> {
                // Simple random
                for (int i = 0; i < length; i++) {
                    key[i] = secureRandom.nextInt(256);
                }
            }
            case 2 -> {
                // Pattern-based
                int base = secureRandom.nextInt(256);
                int step = secureRandom.nextInt(50) + 1;
                for (int i = 0; i < length; i++) {
                    key[i] = (base + i * step) & 0xFF;
                }
            }
            case 3 -> {
                // Fibonacci-like
                int a = secureRandom.nextInt(100);
                int b = secureRandom.nextInt(100);
                for (int i = 0; i < length; i++) {
                    key[i] = (a + b) & 0xFF;
                    int temp = b;
                    b = a + b;
                    a = temp;
                }
            }
            case 4 -> {
                // XOR cascade
                int seed = secureRandom.nextInt();
                for (int i = 0; i < length; i++) {
                    seed = seed * 1103515245 + 12345;
                    key[i] = (seed >> 16) & 0xFF;
                }
            }
        }

        return key;
    }

    /**
     * Get random transformation strategy by type
     */
    public TransformStrategy getRandomStrategy(StrategyType type) {
        List<TransformStrategy> matching = strategies.stream()
                .filter(s -> s.type() == type)
                .toList();

        if (matching.isEmpty()) {
            return null;
        }

        return matching.get(secureRandom.nextInt(matching.size()));
    }

    /**
     * Generate random salt for key derivation
     */
    public byte[] generateRandomSalt(int length) {
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate random iteration count for PBKDF2 (5000-50000)
     */
    public int getRandomIterationCount() {
        return getRandomInt(5000, 50000);
    }

    /**
     * Generate random substitution table
     */
    public byte[] generateRandomSubstitutionTable() {
        byte[] table = new byte[256];
        for (int i = 0; i < 256; i++) {
            table[i] = (byte) i;
        }

        // Multiple shuffle passes with random count
        int shufflePasses = getRandomInt(3, 10);
        for (int pass = 0; pass < shufflePasses; pass++) {
            for (int i = 255; i > 0; i--) {
                int j = secureRandom.nextInt(i + 1);
                byte temp = table[i];
                table[i] = table[j];
                table[j] = temp;
            }
        }

        return table;
    }

    /**
     * Get underlying SecureRandom instance
     */
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    /**
     * Transformation strategy record
     */
    public record TransformStrategy(String name, StrategyType type) {
    }

    /**
     * Strategy types
     */
    public enum StrategyType {
        STRING_ENCRYPT,
        CONTROL_FLOW,
        DEAD_CODE,
        ANTI_DEBUG,
        REFERENCE_HIDE
    }
}
