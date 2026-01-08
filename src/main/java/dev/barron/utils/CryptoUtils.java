package dev.barron.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Advanced cryptographic utilities for string encryption
 * Uses multi-layer encryption with AES-256-GCM + XOR + Substitution
 * Keys are fragmented and derived at runtime for maximum security
 */
public class CryptoUtils {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 10000;

    private final SecureRandom secureRandom = new SecureRandom();

    // Master key fragments - will be reconstructed at runtime
    private final byte[] keyFragment1;
    private final byte[] keyFragment2;
    private final byte[] keyFragment3;
    private final byte[] keyFragment4;

    // Salt for key derivation
    private final byte[] salt;

    // Session-specific values
    private final long sessionSeed;
    private final byte[] substitutionTable;
    private final byte[] inverseSubstitutionTable;

    /**
     * Create a new CryptoUtils with fragmented random keys
     * Each obfuscation session gets unique keys
     */
    public CryptoUtils() {
        this.sessionSeed = secureRandom.nextLong();
        this.salt = new byte[16];
        secureRandom.nextBytes(salt);

        // Generate master key and fragment it
        byte[] masterKey = generateRandomKey();

        // Fragment the key into 4 parts (8 bytes each)
        this.keyFragment1 = Arrays.copyOfRange(masterKey, 0, 8);
        this.keyFragment2 = Arrays.copyOfRange(masterKey, 8, 16);
        this.keyFragment3 = Arrays.copyOfRange(masterKey, 16, 24);
        this.keyFragment4 = Arrays.copyOfRange(masterKey, 24, 32);

        // Generate substitution table for third encryption layer
        this.substitutionTable = generateSubstitutionTable();
        this.inverseSubstitutionTable = generateInverseSubstitutionTable(substitutionTable);
    }

    /**
     * Generate a random 256-bit AES key
     */
    private byte[] generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE, secureRandom);
            return keyGen.generateKey().getEncoded();
        } catch (Exception e) {
            // Fallback to direct random generation
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);
            return key;
        }
    }

    /**
     * Generate a random substitution table (256 bytes)
     */
    private byte[] generateSubstitutionTable() {
        byte[] table = new byte[256];
        for (int i = 0; i < 256; i++) {
            table[i] = (byte) i;
        }
        // Fisher-Yates shuffle
        for (int i = 255; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            byte temp = table[i];
            table[i] = table[j];
            table[j] = temp;
        }
        return table;
    }

    /**
     * Generate inverse substitution table
     */
    private byte[] generateInverseSubstitutionTable(byte[] table) {
        byte[] inverse = new byte[256];
        for (int i = 0; i < 256; i++) {
            inverse[table[i] & 0xFF] = (byte) i;
        }
        return inverse;
    }

    /**
     * Reconstruct the master key from fragments
     * This adds complexity for decompilers
     */
    private byte[] reconstructMasterKey() {
        byte[] key = new byte[32];
        System.arraycopy(keyFragment1, 0, key, 0, 8);
        System.arraycopy(keyFragment2, 0, key, 8, 8);
        System.arraycopy(keyFragment3, 0, key, 16, 8);
        System.arraycopy(keyFragment4, 0, key, 24, 8);
        return key;
    }

    /**
     * Derive a unique key for a specific string using PBKDF2
     */
    public byte[] deriveStringKey(int stringIndex) {
        try {
            byte[] masterKey = reconstructMasterKey();

            // Create a unique password from master key + index + session
            String password = Base64.getEncoder().encodeToString(masterKey) +
                    ":" + stringIndex + ":" + sessionSeed;

            // Use PBKDF2 for key derivation
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            SecretKey key = factory.generateSecret(spec);

            return key.getEncoded();
        } catch (Exception e) {
            // Fallback to simpler derivation
            return generateStringKey(stringIndex);
        }
    }

    /**
     * Legacy key generation for fallback
     */
    public byte[] generateStringKey(int stringIndex) {
        byte[] masterKey = reconstructMasterKey();
        byte[] uniqueKey = new byte[32];
        SecureRandom seededRandom = new SecureRandom();
        seededRandom.setSeed(sessionSeed ^ stringIndex ^ bytesToLong(masterKey));
        seededRandom.nextBytes(uniqueKey);

        // XOR with master key for additional security
        for (int i = 0; i < 32; i++) {
            uniqueKey[i] ^= masterKey[i];
        }

        return uniqueKey;
    }

    /**
     * Multi-layer encryption: AES-GCM -> XOR -> Substitution
     * This makes static analysis extremely difficult
     */
    public MultiLayerEncryptedString encryptMultiLayer(String plaintext, int stringIndex) {
        try {
            byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);

            // Layer 1: AES-256-GCM encryption
            byte[] derivedKey = deriveStringKey(stringIndex);
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            SecretKey secretKey = new SecretKeySpec(derivedKey, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] aesEncrypted = cipher.doFinal(data);

            // Layer 2: XOR with rolling key
            byte[] xorKey = generateRollingXorKey(aesEncrypted.length, stringIndex);
            byte[] xorEncrypted = new byte[aesEncrypted.length];
            for (int i = 0; i < aesEncrypted.length; i++) {
                xorEncrypted[i] = (byte) (aesEncrypted[i] ^ xorKey[i]);
            }

            // Layer 3: Substitution cipher
            byte[] substituted = new byte[xorEncrypted.length];
            for (int i = 0; i < xorEncrypted.length; i++) {
                substituted[i] = substitutionTable[xorEncrypted[i] & 0xFF];
            }

            return new MultiLayerEncryptedString(
                    substituted,
                    iv,
                    xorKey,
                    stringIndex);
        } catch (Exception e) {
            throw new RuntimeException("Multi-layer encryption failed", e);
        }
    }

    /**
     * Generate a rolling XOR key based on string index
     */
    private byte[] generateRollingXorKey(int length, int stringIndex) {
        byte[] key = new byte[length];
        SecureRandom keyRandom = new SecureRandom();
        keyRandom.setSeed(sessionSeed ^ (stringIndex * 31L));
        keyRandom.nextBytes(key);
        return key;
    }

    /**
     * Simple XOR encryption for less critical strings (maintained for
     * compatibility)
     * Uses a different random key each time
     */
    public XorEncryptedString xorEncrypt(String plaintext) {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[data.length];
        secureRandom.nextBytes(key);

        byte[] encrypted = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            encrypted[i] = (byte) (data[i] ^ key[i]);
        }

        return new XorEncryptedString(encrypted, key);
    }

    /**
     * Enhanced XOR with rolling key for better security
     */
    public EnhancedXorEncryptedString xorEncryptEnhanced(String plaintext, int stringIndex) {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);

        // Generate multiple key components
        byte[] key1 = new byte[data.length];
        byte[] key2 = new byte[data.length];
        secureRandom.nextBytes(key1);
        secureRandom.nextBytes(key2);

        byte[] encrypted = new byte[data.length];

        // Multi-step XOR
        for (int i = 0; i < data.length; i++) {
            int step1 = data[i] ^ key1[i];
            int step2 = step1 ^ key2[i];
            int step3 = step2 ^ ((stringIndex + i) & 0xFF);
            encrypted[i] = (byte) step3;
        }

        return new EnhancedXorEncryptedString(encrypted, key1, key2, stringIndex);
    }

    /**
     * Get the session seed (needed for runtime decryption)
     */
    public long getSessionSeed() {
        return sessionSeed;
    }

    /**
     * Get master key fragments (needed for runtime decryption)
     */
    public byte[][] getKeyFragments() {
        return new byte[][] {
                keyFragment1.clone(),
                keyFragment2.clone(),
                keyFragment3.clone(),
                keyFragment4.clone()
        };
    }

    /**
     * Get salt for PBKDF2
     */
    public byte[] getSalt() {
        return salt.clone();
    }

    /**
     * Get substitution table
     */
    public byte[] getSubstitutionTable() {
        return substitutionTable.clone();
    }

    /**
     * Get inverse substitution table
     */
    public byte[] getInverseSubstitutionTable() {
        return inverseSubstitutionTable.clone();
    }

    private long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < Math.min(8, bytes.length); i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }

    /**
     * Multi-layer encrypted string with all components
     */
    public record MultiLayerEncryptedString(
            byte[] encrypted,
            byte[] iv,
            byte[] xorKey,
            int stringIndex) {
        public int[] getEncryptedAsIntArray() {
            int[] arr = new int[encrypted.length];
            for (int i = 0; i < encrypted.length; i++) {
                arr[i] = encrypted[i] & 0xFF;
            }
            return arr;
        }

        public int[] getIvAsIntArray() {
            int[] arr = new int[iv.length];
            for (int i = 0; i < iv.length; i++) {
                arr[i] = iv[i] & 0xFF;
            }
            return arr;
        }

        public int[] getXorKeyAsIntArray() {
            int[] arr = new int[xorKey.length];
            for (int i = 0; i < xorKey.length; i++) {
                arr[i] = xorKey[i] & 0xFF;
            }
            return arr;
        }
    }

    /**
     * Enhanced XOR encrypted string
     */
    public record EnhancedXorEncryptedString(
            byte[] encrypted,
            byte[] key1,
            byte[] key2,
            int stringIndex) {
        public int[] getEncryptedAsIntArray() {
            int[] arr = new int[encrypted.length];
            for (int i = 0; i < encrypted.length; i++) {
                arr[i] = encrypted[i] & 0xFF;
            }
            return arr;
        }

        public int[] getKey1AsIntArray() {
            int[] arr = new int[key1.length];
            for (int i = 0; i < key1.length; i++) {
                arr[i] = key1[i] & 0xFF;
            }
            return arr;
        }

        public int[] getKey2AsIntArray() {
            int[] arr = new int[key2.length];
            for (int i = 0; i < key2.length; i++) {
                arr[i] = key2[i] & 0xFF;
            }
            return arr;
        }
    }

    /**
     * XOR encrypted string (legacy, maintained for compatibility)
     */
    public record XorEncryptedString(byte[] encrypted, byte[] key) {
        public int[] getEncryptedAsIntArray() {
            int[] arr = new int[encrypted.length];
            for (int i = 0; i < encrypted.length; i++) {
                arr[i] = encrypted[i] & 0xFF;
            }
            return arr;
        }

        public int[] getKeyAsIntArray() {
            int[] arr = new int[key.length];
            for (int i = 0; i < key.length; i++) {
                arr[i] = key[i] & 0xFF;
            }
            return arr;
        }
    }

    /**
     * AES-GCM encrypted string (for high-security strings)
     */
    public record EncryptedString(String ciphertext, String iv, String key) {
    }

    /**
     * Encrypt a string with AES-GCM (for specific high-value strings)
     */
    public EncryptedString encrypt(String plaintext, byte[] key) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return new EncryptedString(
                    Base64.getEncoder().encodeToString(ciphertext),
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(key));
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
}
