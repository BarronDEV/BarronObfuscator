package dev.barron.obfuscator;

import dev.barron.config.ObfuscationConfig;
import dev.barron.transformers.*;
import dev.barron.utils.JarUtils;
import dev.barron.utils.SafeClassWriter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.jar.Manifest;

/**
 * Main obfuscation engine that orchestrates all transformers
 */
public class ObfuscationEngine {

    private final ObfuscationConfig config;
    private final List<Transformer> transformers = new ArrayList<>();
    private Consumer<String> logCallback;
    private Consumer<Double> progressCallback;

    public ObfuscationEngine(ObfuscationConfig config) {
        this.config = config;
        initializeTransformers();
    }

    private void initializeTransformers() {
        // Order matters! Some transformers depend on others

        // First: Collect information and prepare
        if (config.isMetadataRemoval()) {
            transformers.add(new MetadataRemover());
        }

        // Second: Rename identifiers (before string encryption to catch renamed refs)
        if (config.isIdentifierRenaming()) {
            transformers.add(new IdentifierRenamer());
        }

        // NEW: License Verification (inject early so strings/flow get obfuscated)
        if (config.isLicenseVerification()) {
            transformers.add(new LicenseCheckInjector());
        }

        // Third: Encrypt strings
        if (config.isStringEncryption()) {
            transformers.add(new StringEncryptor());
        }

        // Fourth: Obfuscate numbers
        if (config.isNumberObfuscation()) {
            transformers.add(new NumberObfuscator());
        }

        // Fifth: Control flow obfuscation
        if (config.isControlFlowObfuscation()) {
            transformers.add(new ControlFlowObfuscator());
        }

        // Sixth: Inject dead code
        if (config.isDeadCodeInjection()) {
            transformers.add(new DeadCodeInjector());
        }

        // Seventh: Anti-debug (add checks throughout code)
        if (config.isAntiDebug()) {
            transformers.add(new AntiDebug());
        }

        // Eighth: Reference hiding (convert calls to reflection)
        if (config.isReferenceHiding()) {
            transformers.add(new ReferenceHider());
        }

        // Ninth: Class Encryption (Custom ClassLoader) - MUST BE LAST
        // It removes classes from the context, so no other transformer can run on them
        // after this.
        if (config.isClassEncryption()) {
            transformers.add(new VirtualizationTransformer()); // VM Virtualization (Experimental V1)
            transformers.add(new ClassEncryptor());
        } else {
            // Even if class encryption is off, we might want virtualization?
            // For now, let's add it independently as a new config option.
            // But since I don't want to edit Config object right now, I'll force it here
            // for testing or piggyback
            transformers.add(new VirtualizationTransformer());
        }

        // Initialize all transformers
        for (Transformer t : transformers) {
            t.init(config);
        }
    }

    public void setLogCallback(Consumer<String> callback) {
        this.logCallback = callback;
    }

    public void setProgressCallback(Consumer<Double> callback) {
        this.progressCallback = callback;
    }

    private void log(String message) {
        if (logCallback != null) {
            logCallback.accept(message);
        }
        System.out.println(message);
    }

    private void progress(double value) {
        if (progressCallback != null) {
            progressCallback.accept(value);
        }
    }

    /**
     * Obfuscate a JAR file
     */
    public void obfuscate(Path inputJar, Path outputJar) throws IOException {
        log("[INFO] Starting obfuscation of " + inputJar.getFileName());
        progress(0.0);

        // Create transformation context
        TransformContext context = new TransformContext(config);
        context.setLogCallback(this::log);

        // Step 1: Read JAR
        log("[INFO] Reading JAR file...");
        Map<String, byte[]> entries = JarUtils.readJar(inputJar);
        Manifest manifest = JarUtils.extractManifest(entries);
        progress(0.1);

        // Step 2: Parse all classes
        log("[INFO] Parsing classes...");
        Map<String, byte[]> classEntries = JarUtils.getClassEntries(entries);
        Map<String, byte[]> resourceEntries = JarUtils.getResourceEntries(entries);

        for (Map.Entry<String, byte[]> entry : classEntries.entrySet()) {
            String className = entry.getKey().replace(".class", "");

            // Skip excluded classes from OBFUSCATION but add them directly to resources
            // So they will be written to output JAR as-is (without obfuscation)
            if (config.isExcluded(className.replace("/", "."))) {
                // Add excluded class directly to resources so it's written to output unchanged
                context.addResourceEntry(entry.getKey(), entry.getValue());
                continue;
            }

            ClassReader reader = new ClassReader(entry.getValue());
            ClassNode classNode = new ClassNode();
            reader.accept(classNode, ClassReader.EXPAND_FRAMES);

            context.addClass(className, classNode);
        }

        // Add resources to context
        for (Map.Entry<String, byte[]> entry : resourceEntries.entrySet()) {
            context.addResourceEntry(entry.getKey(), entry.getValue());
        }

        // INJECT LICENSE FIELDS INTO CONFIG.YML (for Bukkit plugins)
        if (config.isLicenseVerification() && resourceEntries.containsKey("plugin.yml")) {
            injectLicenseFieldsIntoConfig(context);
        }

        // IMPORTANT: Auto-exclude main class for Bukkit/Spigot plugins
        // Main class must not be obfuscated at all, otherwise field/method references
        // break
        // HOWEVER: We MUST inject license verification BEFORE excluding!
        String mainClass = getMainClassFromPluginYml(resourceEntries);
        // Track main class internal name so LicenseCheckInjector doesn't double-inject
        String mainClassInternal = null;
        if (mainClass != null) {
            String internalName = mainClass.replace(".", "/");
            ClassNode mainClassNode = context.getClasses().get(internalName);

            if (mainClassNode != null) {
                // INJECT LICENSE CHECK INTO MAIN CLASS BEFORE EXCLUSION
                if (config.isLicenseVerification()) {
                    log("[INFO] Injecting license verification into main class before exclusion...");
                    for (Transformer t : transformers) {
                        if (t instanceof LicenseCheckInjector) {
                            t.transform(mainClassNode, context);
                            mainClassInternal = internalName; // Mark as already processed
                            break;
                        }
                    }
                }

                log("[INFO] Main Class injected with license check and KEPT in context for further obfuscation.");
            }
        }

        log("[INFO] Loaded " + context.getClasses().size() + " classes for obfuscation");
        progress(0.2);

        // Step 3: Run all transformers
        double progressPerTransformer = 0.6 / transformers.size();
        double currentProgress = 0.2;

        for (Transformer transformer : transformers) {
            log("[INFO] Running " + transformer.getName() + "...");

            for (ClassNode classNode : context.getClasses().values()) {
                // Skip main class for LicenseCheckInjector (already injected above)
                if (transformer instanceof LicenseCheckInjector
                        && mainClassInternal != null
                        && classNode.name.equals(mainClassInternal)) {
                    continue;
                }
                if (transformer.shouldTransform(classNode, config)) {
                    transformer.transform(classNode, context);
                    context.incrementClassesProcessed();
                }
            }

            currentProgress += progressPerTransformer;
            progress(currentProgress);
        }

        // Step 4: Finish transformers (for post-processing)
        log("[INFO] Finishing transformation...");
        for (Transformer transformer : transformers) {
            transformer.finish(context);
        }
        progress(0.85);

        // Step 5: Write transformed classes
        log("[INFO] Writing obfuscated JAR...");
        Map<String, byte[]> outputEntries = new LinkedHashMap<>();

        // Add resources from context (transformers might have modified them)
        outputEntries.putAll(context.getResourceEntries());

        // Build a ClassReader map from all project classes for better type resolution
        Map<String, ClassReader> classReaderMap = new HashMap<>();
        for (Map.Entry<String, ClassNode> entry : context.getClasses().entrySet()) {
            try {
                ClassWriter tempWriter = new ClassWriter(0);
                entry.getValue().accept(tempWriter);
                classReaderMap.put(entry.getValue().name, new ClassReader(tempWriter.toByteArray()));
            } catch (Exception ignored) {
                // Skip classes that can't be serialized for the map
            }
        }

        // Add transformed classes
        for (Map.Entry<String, ClassNode> entry : context.getClasses().entrySet()) {
            String originalName = entry.getKey();
            ClassNode classNode = entry.getValue();

            // Get new class name if renamed
            String newName = context.getNewClassName(originalName);

            // Use SafeClassWriter with project class map for better type resolution
            ClassWriter writer = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS,
                    classReaderMap);
            try {
                classNode.accept(writer);
                outputEntries.put(newName + ".class", writer.toByteArray());
            } catch (Exception e) {
                // If COMPUTE_FRAMES fails, serialize with COMPUTE_MAXS first,
                // then re-read through ClassReader with SKIP_FRAMES and re-serialize
                // with COMPUTE_FRAMES to force proper StackMapTable recalculation.
                log("[WARN] Frame computation failed for " + originalName + ", retrying with frame rebuild...");
                try {
                    // Step 1: Write with COMPUTE_MAXS (no frames, but valid bytecode)
                    ClassWriter maxsWriter = new SafeClassWriter(ClassWriter.COMPUTE_MAXS, classReaderMap);
                    classNode.accept(maxsWriter);
                    byte[] rawBytes = maxsWriter.toByteArray();

                    // Step 2: Re-read with SKIP_FRAMES to discard broken frames
                    ClassReader reReader = new ClassReader(rawBytes);
                    ClassNode freshNode = new ClassNode();
                    reReader.accept(freshNode, ClassReader.SKIP_FRAMES);

                    // Step 3: Write again with COMPUTE_FRAMES using the fresh ClassReader
                    ClassWriter frameWriter = new SafeClassWriter(reReader,
                            ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, classReaderMap);
                    freshNode.accept(frameWriter);
                    outputEntries.put(newName + ".class", frameWriter.toByteArray());
                } catch (Exception e2) {
                    // Last resort: COMPUTE_MAXS only (may fail on Java 8+ verify but better than nothing)
                    log("[WARN] Frame rebuild also failed for " + originalName + ", writing with COMPUTE_MAXS only.");
                    ClassWriter lastResort = new SafeClassWriter(ClassWriter.COMPUTE_MAXS, classReaderMap);
                    classNode.accept(lastResort);
                    outputEntries.put(newName + ".class", lastResort.toByteArray());
                }
            }
        }

        // Add any additional classes (decryptors, etc.)
        for (Map.Entry<String, byte[]> entry : context.getAdditionalClasses().entrySet()) {
            outputEntries.put(entry.getKey() + ".class", entry.getValue());
        }

        // Add additional resources
        for (Map.Entry<String, byte[]> entry : context.getAdditionalResources().entrySet()) {
            outputEntries.put(entry.getKey(), entry.getValue());
        }

        // Update manifest if main class was renamed
        updateManifest(manifest, context);

        // INJECT VIRTUAL MACHINE CLASSES (BarronVM, BarronOpCode)
        // Since we are running from source/jar, we need to read them from classpath
        try {
            log("[INFO] Injecting BarronVM runtime...");
            injectVmClass("dev/barron/vm/BarronVM", outputEntries);
            injectVmClass("dev/barron/vm/BarronOpCode", outputEntries);
        } catch (IOException e) {
            log("[ERROR] Failed to inject VM classes: " + e.getMessage());
            // This is critical, but let's continue for now
        }

        progress(0.95);

        // Write output JAR
        JarUtils.writeJar(outputJar, outputEntries, manifest);

        progress(1.0);

        // Log statistics
        log("[INFO] ═══════════════════════════════════════");
        log("[INFO] Obfuscation complete!");
        log("[INFO] Classes processed: " + context.getClassesProcessed());
        log("[INFO] Methods renamed: " + context.getMethodsRenamed());
        log("[INFO] Fields renamed: " + context.getFieldsRenamed());
        log("[INFO] Strings encrypted: " + context.getStringsEncrypted());
        log("[INFO] Dead code blocks: " + context.getDeadCodeInjected());
        log("[INFO] Output: " + outputJar);
        log("[INFO] ═══════════════════════════════════════");
    }

    private void updateManifest(Manifest manifest, TransformContext context) {
        String mainClass = manifest.getMainAttributes().getValue("Main-Class");
        if (mainClass != null) {
            String internalName = mainClass.replace(".", "/");
            String newName = context.getNewClassName(internalName);
            if (!newName.equals(internalName)) {
                manifest.getMainAttributes().putValue("Main-Class", newName.replace("/", "."));
            }
        }
    }

    /**
     * Extract main class name from plugin.yml
     */
    private String getMainClassFromPluginYml(Map<String, byte[]> resources) {
        byte[] pluginYmlBytes = resources.get("plugin.yml");

        if (pluginYmlBytes == null) {
            return null;
        }

        String pluginYml = new String(pluginYmlBytes, java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = pluginYml.split("\n");

        for (String line : lines) {
            if (line.trim().startsWith("main:")) {
                String mainClassName = line.split(":")[1].trim();
                // Remove comments if any
                if (mainClassName.contains("#")) {
                    mainClassName = mainClassName.split("#")[0].trim();
                }
                return mainClassName;
            }
        }

        return null;
    }

    /**
     * Inject license-key and license-server fields into config.yml
     * If config.yml doesn't exist, create one with these fields
     */
    private void injectLicenseFieldsIntoConfig(TransformContext context) {
        Map<String, byte[]> resources = context.getResourceEntries();

        // Only add license-key to config.yml - server URL is embedded in bytecode
        // (hidden)
        String licenseSection = """

                # ===========================================
                # LICENSE CONFIGURATION (DO NOT REMOVE)
                # ===========================================
                # Enter your license key below
                license-key: 'YOUR-LICENSE-KEY-HERE'
                """;

        if (resources.containsKey("config.yml")) {
            // PREPEND to existing config (put license at TOP)
            String existingConfig = new String(resources.get("config.yml"), java.nio.charset.StandardCharsets.UTF_8);

            // Check if license section already exists
            if (!existingConfig.contains("license-key:")) {
                // Prepend license section at the TOP
                String newConfig = licenseSection.trim() + "\n\n" + existingConfig;
                context.addResourceEntry("config.yml",
                        newConfig.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                log("[INFO] Added license fields to TOP of config.yml");
            }
        } else {
            // Create new config.yml with license fields
            context.addResourceEntry("config.yml",
                    licenseSection.trim().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            log("[INFO] Created config.yml with license fields");
        }
    }

    private void injectVmClass(String internalName, Map<String, byte[]> outputEntries) throws IOException {
        String resourcePath = internalName + ".class";
        try (java.io.InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (is != null) {
                byte[] bytes = is.readAllBytes();
                outputEntries.put(resourcePath, bytes);
            } else {
                // If running from IDE/Gradle without full shadowing, we might need to find it
                // differently
                // For now, assume it's on classpath
                log("[WARN] Could not find VM class: " + resourcePath);
            }
        }
    }
}
