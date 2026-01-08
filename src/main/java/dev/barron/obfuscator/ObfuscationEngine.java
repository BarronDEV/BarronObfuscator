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

            // Skip excluded classes
            if (config.isExcluded(className.replace("/", "."))) {
                log("[SKIP] Excluded: " + className);
                continue;
            }

            ClassReader reader = new ClassReader(entry.getValue());
            ClassNode classNode = new ClassNode();
            reader.accept(classNode, ClassReader.EXPAND_FRAMES);

            context.addClass(className, classNode);
        }

        log("[INFO] Loaded " + context.getClasses().size() + " classes for obfuscation");
        progress(0.2);

        // Step 3: Run all transformers
        double progressPerTransformer = 0.6 / transformers.size();
        double currentProgress = 0.2;

        for (Transformer transformer : transformers) {
            log("[INFO] Running " + transformer.getName() + "...");

            for (ClassNode classNode : context.getClasses().values()) {
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

        // Add resources (unchanged)
        outputEntries.putAll(resourceEntries);

        // Add transformed classes
        for (Map.Entry<String, ClassNode> entry : context.getClasses().entrySet()) {
            String originalName = entry.getKey();
            ClassNode classNode = entry.getValue();

            // Get new class name if renamed
            String newName = context.getNewClassName(originalName);

            // Use SafeClassWriter to handle missing types on classpath
            ClassWriter writer = new SafeClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS,
                    Collections.emptyMap());
            try {
                classNode.accept(writer);
                outputEntries.put(newName + ".class", writer.toByteArray());
            } catch (Exception e) {
                // If COMPUTE_FRAMES fails, try with just COMPUTE_MAXS
                log("[WARN] Frame computation failed for " + originalName + ", retrying without frames...");
                writer = new SafeClassWriter(ClassWriter.COMPUTE_MAXS, Collections.emptyMap());
                classNode.accept(writer);
                outputEntries.put(newName + ".class", writer.toByteArray());
            }
        }

        // Add any additional classes (decryptors, etc.)
        for (Map.Entry<String, byte[]> entry : context.getAdditionalClasses().entrySet()) {
            outputEntries.put(entry.getKey() + ".class", entry.getValue());
        }

        // Update manifest if main class was renamed
        updateManifest(manifest, context);

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
}
