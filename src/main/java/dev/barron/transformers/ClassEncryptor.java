package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.tree.ClassNode;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * Class Encryptor with AES-256-GCM encryption, key obfuscation, and integrity
 * checks.
 * Provides strong protection for non-Bukkit JARs.
 */
public class ClassEncryptor implements Transformer {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;
    private static final byte VERSION_AES_GCM = 1;

    private final List<String> classesToEncrypt = new ArrayList<>();
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String getName() {
        return "Class Encryptor (AES-256-GCM)";
    }

    @Override
    public void init(ObfuscationConfig config) {
        // Init
    }

    @Override
    public boolean shouldTransform(ClassNode classNode, ObfuscationConfig config) {
        return config.isClassEncryption();
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        classesToEncrypt.add(classNode.name);
        return false;
    }

    @Override
    public void finish(TransformContext context) {
        if (!context.getConfig().isClassEncryption() || classesToEncrypt.isEmpty()) {
            return;
        }

        // Check if this is a Bukkit/Spigot plugin
        Map<String, byte[]> resources = context.getResourceEntries();
        if (resources.containsKey("plugin.yml")) {
            context.log("[WARN] Class Encryption is not compatible with Bukkit/Spigot plugins.");
            context.log("[INFO] Your plugin is still protected by: String Encryption, Identifier Renaming,");
            context.log("[INFO] Control Flow Obfuscation, Dead Code Injection, and Anti-Debug features.");
            classesToEncrypt.clear();
            return;
        }

        if (classesToEncrypt.isEmpty()) {
            return;
        }

        context.log("[INFO] Encrypting " + classesToEncrypt.size() + " classes with AES-256-GCM...");

        // Generate cryptographic materials
        String masterKey = UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
        String salt = generateSalt();
        byte[] derivedKey = deriveKey(masterKey, salt);

        // Track successfully encrypted classes
        List<String> successfullyEncrypted = new ArrayList<>();

        // Prepare binary data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            ByteArrayOutputStream classData = new ByteArrayOutputStream();
            DataOutputStream classDataDos = new DataOutputStream(classData);

            for (String className : classesToEncrypt) {
                ClassNode node = context.getClass(className);
                if (node == null) {
                    context.logWarning("Class not found in context: " + className);
                    continue;
                }

                try {
                    byte[] classBytes;
                    try {
                        org.objectweb.asm.ClassWriter frameWriter = new dev.barron.utils.SafeClassWriter(
                                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES
                                        | org.objectweb.asm.ClassWriter.COMPUTE_MAXS,
                                new HashMap<>());
                        node.accept(frameWriter);
                        classBytes = frameWriter.toByteArray();
                    } catch (Exception frameEx) {
                        context.logWarning(
                                "Frame computation failed for " + className + ", using COMPUTE_MAXS fallback");
                        org.objectweb.asm.ClassWriter maxsWriter = new dev.barron.utils.SafeClassWriter(
                                org.objectweb.asm.ClassWriter.COMPUTE_MAXS, new HashMap<>());
                        node.accept(maxsWriter);
                        classBytes = maxsWriter.toByteArray();
                    }

                    // Encrypt with AES-GCM
                    byte[] encrypted = encryptAES(classBytes, derivedKey);

                    // Write to format
                    byte[] nameBytes = className.getBytes(StandardCharsets.UTF_8);
                    classDataDos.writeInt(nameBytes.length);
                    classDataDos.write(nameBytes);
                    classDataDos.writeInt(encrypted.length);
                    classDataDos.write(encrypted);

                    successfullyEncrypted.add(className);

                } catch (Exception e) {
                    context.logError("Failed to encrypt class " + className + ": " + e.getMessage());
                }
            }

            // Write version byte + class count + class data
            dos.writeByte(VERSION_AES_GCM);
            dos.writeInt(successfullyEncrypted.size());
            dos.write(classData.toByteArray());

            // Remove encrypted classes from context
            for (String className : successfullyEncrypted) {
                context.getClasses().remove(className);
            }

            context.log("[INFO] Successfully encrypted " + successfullyEncrypted.size() + "/"
                    + classesToEncrypt.size() + " classes");

        } catch (IOException e) {
            context.logError("Class encryption failed: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        if (!successfullyEncrypted.isEmpty()) {
            // Add encrypted data resource
            byte[] encryptedData = baos.toByteArray();
            context.addResourceEntry("barron.data", encryptedData);

            // Obfuscate the key
            String obfuscatedKey = obfuscateKey(masterKey, salt);

            // Create barron.meta with obfuscated key
            String metaContent = createMetaContent(null, obfuscatedKey, salt, encryptedData);
            byte[] metaBytes = metaContent.getBytes(StandardCharsets.UTF_8);
            context.addResourceEntry("barron.meta", metaBytes);

            // Calculate integrity hash (hash of barron.data + barron.meta)
            String integrityHash = calculateIntegrityHash(encryptedData, metaBytes);

            // Update meta with integrity hash
            metaContent = createMetaContent(null, obfuscatedKey, salt, encryptedData)
                    + "\nintegrity=" + integrityHash;
            context.addResourceEntry("barron.meta", metaContent.getBytes(StandardCharsets.UTF_8));

            // Add loader classes
            ClassLoader myLoader = getClass().getClassLoader();
            addLoaderClass(context, myLoader, "dev/barron/loader/BarronClassLoader");

            context.log("[INFO] Encryption complete with AES-256-GCM + PBKDF2 key derivation");
            context.log("[INFO] Integrity hash: " + integrityHash.substring(0, 16) + "...");
        }
    }

    /**
     * Encrypt data using AES-256-GCM
     * Output format: [IV (12 bytes)] [Ciphertext + Auth Tag]
     */
    private byte[] encryptAES(byte[] data, byte[] key) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Setup cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(data);

        // Combine IV + ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
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
            // Fallback to SHA-256
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                return md.digest(password.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ex) {
                return password.getBytes(StandardCharsets.UTF_8);
            }
        }
    }

    /**
     * Generate cryptographically secure salt
     */
    private String generateSalt() {
        byte[] saltBytes = new byte[16];
        secureRandom.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /**
     * Obfuscate the key by XOR'ing with salt and Base64 encoding
     */
    private String obfuscateKey(String key, String salt) {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        byte[] obfuscated = new byte[keyBytes.length];

        for (int i = 0; i < keyBytes.length; i++) {
            obfuscated[i] = (byte) (keyBytes[i] ^ saltBytes[i % saltBytes.length]);
        }

        return Base64.getEncoder().encodeToString(obfuscated);
    }

    /**
     * Create meta content for barron.meta file
     */
    private String createMetaContent(String mainClass, String obfuscatedKey, String salt, byte[] data) {
        StringBuilder sb = new StringBuilder();
        if (mainClass != null) {
            sb.append("main=").append(mainClass).append("\n");
        }
        sb.append("key=").append(obfuscatedKey).append("\n");
        sb.append("salt=").append(salt).append("\n");
        sb.append("version=2"); // Version 2 = AES-GCM
        return sb.toString();
    }

    /**
     * Calculate integrity hash of encrypted data
     */
    private String calculateIntegrityHash(byte[] encryptedData, byte[] metaData) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(encryptedData);
            // Don't include meta in hash since meta contains the hash itself
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Add loader class to output JAR
     */
    private void addLoaderClass(TransformContext context, ClassLoader loader, String className) {
        try (InputStream is = loader.getResourceAsStream(className + ".class")) {
            if (is != null) {
                context.addAdditionalClass(className, is.readAllBytes());
            } else {
                context.logError("Could not find " + className + ".class in classpath!");
            }
        } catch (IOException e) {
            context.logError("Failed to add loader class: " + e.getMessage());
        }
    }
}
