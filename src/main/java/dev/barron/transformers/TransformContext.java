package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import dev.barron.utils.CryptoUtils;
import dev.barron.utils.MappingGenerator;
import dev.barron.utils.NameGenerator;
import dev.barron.utils.RandomizationEngine;
import org.objectweb.asm.tree.ClassNode;

import java.util.*;

/**
 * Context shared between all transformers during obfuscation
 * Contains shared state like name mappings, crypto keys, randomization, etc.
 */
public class TransformContext {

    private final ObfuscationConfig config;
    private final CryptoUtils crypto;
    private final RandomizationEngine randomEngine;
    private final NameGenerator classNameGenerator;
    private final NameGenerator methodNameGenerator;
    private final NameGenerator fieldNameGenerator;
    private final MappingGenerator mappingGenerator;

    // All classes being processed
    private final Map<String, ClassNode> classes = new LinkedHashMap<>();

    // Additional classes to add (helper classes, decryptors, etc.)
    private final Map<String, byte[]> additionalClasses = new LinkedHashMap<>();

    // Class name remapping (old internal name -> new internal name)
    private final Map<String, String> classRemapping = new HashMap<>();

    // Method remapping (className.methodName+descriptor -> new method name)
    private final Map<String, String> methodRemapping = new HashMap<>();

    // Field remapping (className.fieldName -> new field name)
    private final Map<String, String> fieldRemapping = new HashMap<>();

    // Encrypted strings registry (for generating decryptor)
    private final List<EncryptedStringEntry> encryptedStrings = new ArrayList<>();

    // Statistics
    private int classesProcessed = 0;
    private int methodsRenamed = 0;
    private int fieldsRenamed = 0;
    private int stringsEncrypted = 0;
    private int deadCodeInjected = 0;

    // Logging callback
    private LogCallback logCallback;

    public TransformContext(ObfuscationConfig config) {
        this.config = config;
        this.crypto = new CryptoUtils();
        this.randomEngine = new RandomizationEngine();
        this.mappingGenerator = new MappingGenerator();

        // Each generator gets a unique random seed
        this.classNameGenerator = new NameGenerator(crypto.getSessionSeed());
        this.methodNameGenerator = new NameGenerator(crypto.getSessionSeed() ^ 0xDEADBEEF);
        this.fieldNameGenerator = new NameGenerator(crypto.getSessionSeed() ^ 0xCAFEBABE);
    }

    // Getters
    public ObfuscationConfig getConfig() {
        return config;
    }

    public CryptoUtils getCrypto() {
        return crypto;
    }

    public RandomizationEngine getRandomEngine() {
        return randomEngine;
    }

    public NameGenerator getClassNameGenerator() {
        return classNameGenerator;
    }

    public NameGenerator getMethodNameGenerator() {
        return methodNameGenerator;
    }

    public NameGenerator getFieldNameGenerator() {
        return fieldNameGenerator;
    }

    public MappingGenerator getMappingGenerator() {
        return mappingGenerator;
    }

    // Class management
    public void addClass(String name, ClassNode node) {
        classes.put(name, node);
    }

    public ClassNode getClass(String name) {
        return classes.get(name);
    }

    public Map<String, ClassNode> getClasses() {
        return classes;
    }

    public void addAdditionalClass(String name, byte[] bytecode) {
        additionalClasses.put(name, bytecode);
    }

    public Map<String, byte[]> getAdditionalClasses() {
        return additionalClasses;
    }

    // Remapping
    public void addClassRemapping(String oldName, String newName) {
        classRemapping.put(oldName, newName);
    }

    public String getNewClassName(String oldName) {
        return classRemapping.getOrDefault(oldName, oldName);
    }

    public Map<String, String> getClassRemapping() {
        return classRemapping;
    }

    public void addMethodRemapping(String className, String methodName, String descriptor, String newName) {
        methodRemapping.put(className + "." + methodName + descriptor, newName);
    }

    public String getNewMethodName(String className, String methodName, String descriptor) {
        return methodRemapping.getOrDefault(className + "." + methodName + descriptor, methodName);
    }

    public void addFieldRemapping(String className, String fieldName, String newName) {
        fieldRemapping.put(className + "." + fieldName, newName);
    }

    public String getNewFieldName(String className, String fieldName) {
        return fieldRemapping.getOrDefault(className + "." + fieldName, fieldName);
    }

    // Encrypted strings
    public void addEncryptedString(String original, int[] encrypted, int[] key) {
        encryptedStrings.add(new EncryptedStringEntry(original, encrypted, key, encryptedStrings.size()));
        stringsEncrypted++;
    }

    public List<EncryptedStringEntry> getEncryptedStrings() {
        return encryptedStrings;
    }

    // Statistics
    public void incrementClassesProcessed() {
        classesProcessed++;
    }

    public void incrementMethodsRenamed() {
        methodsRenamed++;
    }

    public void incrementFieldsRenamed() {
        fieldsRenamed++;
    }

    public void incrementDeadCodeInjected() {
        deadCodeInjected++;
    }

    public int getClassesProcessed() {
        return classesProcessed;
    }

    public int getMethodsRenamed() {
        return methodsRenamed;
    }

    public int getFieldsRenamed() {
        return fieldsRenamed;
    }

    public int getStringsEncrypted() {
        return stringsEncrypted;
    }

    public int getDeadCodeInjected() {
        return deadCodeInjected;
    }

    // Logging
    public void setLogCallback(LogCallback callback) {
        this.logCallback = callback;
    }

    public void log(String message) {
        if (logCallback != null) {
            logCallback.log(message);
        } else {
            System.out.println(message);
        }
    }

    public void logInfo(String message) {
        log("[INFO] " + message);
    }

    public void logWarning(String message) {
        log("[WARN] " + message);
    }

    public void logError(String message) {
        log("[ERROR] " + message);
    }

    /**
     * Check if a class is part of the obfuscation target (not a library)
     */
    public boolean isTargetClass(String internalName) {
        return classes.containsKey(internalName);
    }

    /**
     * Entry for an encrypted string
     */
    public record EncryptedStringEntry(String original, int[] encrypted, int[] key, int index) {
    }

    /**
     * Callback for logging
     */
    @FunctionalInterface
    public interface LogCallback {
        void log(String message);
    }
}
