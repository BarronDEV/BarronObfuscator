package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.tree.ClassNode;

/**
 * Base interface for all obfuscation transformers
 */
public interface Transformer {

    /**
     * Get the name of this transformer
     */
    String getName();

    /**
     * Initialize the transformer with config
     */
    void init(ObfuscationConfig config);

    /**
     * Transform a class
     * 
     * @param classNode The class to transform
     * @param context   The transformation context with shared state
     * @return true if the class was modified
     */
    boolean transform(ClassNode classNode, TransformContext context);

    /**
     * Called after all classes have been transformed
     * Use for any post-processing or injecting helper classes
     */
    default void finish(TransformContext context) {
    }

    /**
     * Check if this transformer should process the given class
     */
    default boolean shouldTransform(ClassNode classNode, ObfuscationConfig config) {
        String className = classNode.name.replace("/", ".");
        return !config.isExcluded(className);
    }
}
