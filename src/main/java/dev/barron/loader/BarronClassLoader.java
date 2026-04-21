package dev.barron.loader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Custom ClassLoader for loading encrypted classes at runtime.
 * Uses AES-256-GCM for strong encryption.
 * This class is injected into the protected JAR.
 */
public class BarronClassLoader extends ClassLoader {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;

    private final Map<String, byte[]> classCache = new HashMap<>();
    private final byte[] derivedKey;
    private final String integrityHash;

    public BarronClassLoader(ClassLoader parent, String obfuscatedKey, String salt, String integrityHash) {
        super(parent);
        this.integrityHash = integrityHash;
        // Deobfuscate and derive the actual encryption key
        String realKey = deobfuscateKey(obfuscatedKey, salt);
        this.derivedKey = deriveKey(realKey, salt);

        // Verify JAR integrity before loading classes
        if (!verifyIntegrity()) {
            throw new SecurityException("JAR integrity check failed - possible tampering detected");
        }

        loadEncryptedClasses();
    }

    // Legacy constructor for backwards compatibility
    public BarronClassLoader(ClassLoader parent, String key) {
        super(parent);
        this.integrityHash = null;
        // Simple key derivation for legacy mode
        this.derivedKey = simpleKeyDerive(key);
        loadEncryptedClasses();
    }

    /**
     * Deobfuscate the key stored in barron.meta
     * Key is XOR'd with salt and Base64 encoded
     */
    private String deobfuscateKey(String obfuscatedKey, String salt) {
        try {
            byte[] encoded = Base64.getDecoder().decode(obfuscatedKey);
            byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[encoded.length];
            for (int i = 0; i < encoded.length; i++) {
                result[i] = (byte) (encoded[i] ^ saltBytes[i % saltBytes.length]);
            }
            return new String(result, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Fallback - treat as plain key
            return obfuscatedKey;
        }
    }

    /**
     * Derive AES-256 key using PBKDF2
     */
    private byte[] deriveKey(String password, String salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt.getBytes(StandardCharsets.UTF_8),
                    PBKDF2_ITERATIONS,
                    KEY_LENGTH);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            // Fallback to simple key derivation
            return simpleKeyDerive(password);
        }
    }

    /**
     * Simple key derivation fallback using SHA-256
     */
    private byte[] simpleKeyDerive(String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(key.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return key.getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * Verify JAR integrity by checking hash of critical resources
     */
    private boolean verifyIntegrity() {
        if (integrityHash == null || integrityHash.isEmpty()) {
            return true; // No integrity check configured
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Hash the encrypted data file
            try (InputStream is = getResourceAsStream("barron.data")) {
                if (is != null) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        md.update(buffer, 0, read);
                    }
                }
            }

            // Hash the meta file
            try (InputStream is = getResourceAsStream("barron.meta")) {
                if (is != null) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        md.update(buffer, 0, read);
                    }
                }
            }

            String computedHash = Base64.getEncoder().encodeToString(md.digest());
            return computedHash.equals(integrityHash);
        } catch (Exception e) {
            return false;
        }
    }

    private void loadEncryptedClasses() {
        try (InputStream is = getResourceAsStream("barron.data")) {
            if (is == null)
                return;

            // Binary format:
            // [Version: byte] (1 = AES-GCM, 0 = legacy XOR)
            // [Total Classes: int]
            // [Name Len: int] [Name: bytes]
            // [Data Len: int] [Data: bytes (IV + ciphertext for AES)]

            int version = is.read();
            int totalClasses = readInt(is);

            for (int i = 0; i < totalClasses; i++) {
                String name = readString(is);
                byte[] data = readBytes(is);
                classCache.put(name, data);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] encrypted = classCache.get(name.replace('.', '/'));
        if (encrypted != null) {
            byte[] decrypted = decryptAES(encrypted);
            if (decrypted == null) {
                throw new ClassNotFoundException("Decryption failed for: " + name);
            }
            return defineClass(name, decrypted, 0, decrypted.length);
        }
        return super.findClass(name);
    }

    /**
     * Decrypt data using AES-256-GCM
     * Format: [IV (12 bytes)] [Ciphertext + Auth Tag]
     */
    private byte[] decryptAES(byte[] data) {
        try {
            if (data.length < GCM_IV_LENGTH) {
                return decryptLegacy(data); // Fallback to XOR
            }

            // Extract IV
            byte[] iv = Arrays.copyOfRange(data, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length);

            // Setup cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(derivedKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Try legacy XOR decryption as fallback
            return decryptLegacy(data);
        }
    }

    /**
     * Legacy XOR decryption for backwards compatibility
     */
    private byte[] decryptLegacy(byte[] data) {
        byte[] output = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            output[i] = (byte) (data[i] ^ derivedKey[i % derivedKey.length]);
        }
        return output;
    }

    // Helper methods for reading binary format
    private int readInt(InputStream is) throws IOException {
        int ch1 = is.read();
        int ch2 = is.read();
        int ch3 = is.read();
        int ch4 = is.read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new IOException("EOF");
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
    }

    private String readString(InputStream is) throws IOException {
        int len = readInt(is);
        byte[] bytes = new byte[len];
        int read = is.read(bytes);
        if (read != len)
            throw new IOException("Read error");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] readBytes(InputStream is) throws IOException {
        int len = readInt(is);
        byte[] bytes = new byte[len];
        int read = 0;
        while (read < len) {
            int c = is.read(bytes, read, len - read);
            if (c == -1)
                break;
            read += c;
        }
        return bytes;
    }
}
