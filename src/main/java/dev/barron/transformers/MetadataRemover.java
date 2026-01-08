package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Removes debug metadata from classes
 * - Line numbers
 * - Source file names
 * - Local variable tables
 * - Local variable type tables
 */
public class MetadataRemover implements Transformer {

    @Override
    public String getName() {
        return "Metadata Remover";
    }

    @Override
    public void init(ObfuscationConfig config) {
        // No initialization needed
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        // Remove source file name
        if (classNode.sourceFile != null) {
            classNode.sourceFile = null;
            modified = true;
        }

        // Remove source debug extension
        if (classNode.sourceDebug != null) {
            classNode.sourceDebug = null;
            modified = true;
        }

        // Remove outer class info (optional, can break some reflection)
        // classNode.outerClass = null;
        // classNode.outerMethod = null;
        // classNode.outerMethodDesc = null;

        // Process methods
        for (MethodNode method : classNode.methods) {
            // Remove local variable table
            if (method.localVariables != null && !method.localVariables.isEmpty()) {
                method.localVariables.clear();
                modified = true;
            }

            // Remove local variable type table (for generics)
            if (method.visibleLocalVariableAnnotations != null) {
                method.visibleLocalVariableAnnotations.clear();
                modified = true;
            }

            if (method.invisibleLocalVariableAnnotations != null) {
                method.invisibleLocalVariableAnnotations.clear();
                modified = true;
            }

            // Remove parameter names (keep parameter annotations though)
            if (method.parameters != null && !method.parameters.isEmpty()) {
                method.parameters.clear();
                modified = true;
            }
        }

        if (modified) {
            context.logInfo("Removed metadata from " + classNode.name);
        }

        return modified;
    }
}
