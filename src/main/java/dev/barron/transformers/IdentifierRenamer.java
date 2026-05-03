package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Renames classes, methods, and fields to obfuscated names
 * Respects Minecraft plugin conventions (keeps event handlers, commands, etc.)
 */
public class IdentifierRenamer implements Transformer {

    private ObfuscationConfig config;
    private boolean isBukkitPluginChecked = false;

    // Annotations that indicate method should keep its name
    private static final Set<String> KEEP_ANNOTATIONS = Set.of(
            "Lorg/bukkit/event/EventHandler;",
            "Lorg/spigotmc/event/player/PlayerSpawnLocationEvent;",
            "Ljavax/annotation/PostConstruct;",
            "Ljavax/annotation/PreDestroy;");

    // Method names to always keep
    private static final Set<String> KEEP_METHODS = Set.of(
            "onEnable", "onDisable", "onLoad",
            "onCommand", "onTabComplete",
            "run", "call", "accept", "apply", "test", "get", "compare",
            "hashCode", "equals", "toString", "clone",
            "main", "<init>", "<clinit>",
            "valueOf", "values" // enum methods
    );

    @Override
    public String getName() {
        return "Identifier Renamer";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        // Check once if this is a Bukkit plugin (only on first class)
        if (!isBukkitPluginChecked) {
            isBukkitPluginChecked = true;
            checkIfBukkitPlugin(context);
        }

        // First pass: collect all renameable identifiers
        // We need to process all classes first before renaming

        // Don't rename main plugin class (referenced in plugin.yml)
        // We'll detect it by checking if it extends JavaPlugin
        boolean isMainClass = isPluginMainClass(classNode);

        // Rename class (but keep simple name pattern for main class)
        if (!isMainClass && shouldRenameClass(classNode)) {
            String oldName = classNode.name;
            String newName = generateNewClassName(oldName, context);

            context.addClassRemapping(oldName, newName);
            modified = true;

            context.logInfo("Renamed class: " + oldName + " -> " + newName);
        }

        // Rename methods
        for (MethodNode method : classNode.methods) {
            if (shouldRenameMethod(classNode, method)) {
                String oldName = method.name;
                String newName = context.getMethodNameGenerator().generateName(
                        classNode.name + "." + oldName + method.desc);

                context.addMethodRemapping(classNode.name, oldName, method.desc, newName);
                method.name = newName;
                context.incrementMethodsRenamed();
                modified = true;
            }
        }

        // Rename fields
        for (FieldNode field : classNode.fields) {
            if (shouldRenameField(classNode, field)) {
                String oldName = field.name;
                String newName = context.getFieldNameGenerator().generateName(
                        classNode.name + "." + oldName + ":" + field.desc);

                context.addFieldRemapping(classNode.name, oldName, field.desc, newName);
                field.name = newName;
                context.incrementFieldsRenamed();
                modified = true;
            }
        }

        return modified;
    }

    @Override
    public void finish(TransformContext context) {
        // Second pass: update all references to renamed identifiers
        Map<String, String> classRemapping = context.getClassRemapping();

        if (classRemapping.isEmpty()) {
            return;
        }

        Remapper remapper = new Remapper() {
            @Override
            public String map(String internalName) {
                return classRemapping.getOrDefault(internalName, internalName);
            }
        };

        // Update all classes with new references
        for (ClassNode classNode : context.getClasses().values()) {
            // Update superclass
            if (classNode.superName != null) {
                classNode.superName = remapper.map(classNode.superName);
            }

            // Update interfaces
            if (classNode.interfaces != null) {
                ListIterator<String> it = classNode.interfaces.listIterator();
                while (it.hasNext()) {
                    it.set(remapper.map(it.next()));
                }
            }

            // Update class name
            String newClassName = classRemapping.get(classNode.name);
            if (newClassName != null) {
                classNode.name = newClassName;
            }

            // Update field descriptors
            for (FieldNode field : classNode.fields) {
                field.desc = remapper.mapDesc(field.desc);
                if (field.signature != null) {
                    field.signature = remapper.mapSignature(field.signature, true);
                }
            }

            // Update method descriptors and instructions
            for (MethodNode method : classNode.methods) {
                method.desc = remapper.mapMethodDesc(method.desc);
                if (method.signature != null) {
                    method.signature = remapper.mapSignature(method.signature, false);
                }

                // Update instructions
                if (method.instructions != null) {
                    for (AbstractInsnNode insn : method.instructions) {
                        if (insn instanceof MethodInsnNode min) {
                            // UPDATE NAME FIRST (using original descriptor)
                            String newName = context.getNewMethodName(min.owner, min.name, min.desc);
                            if (newName != null) {
                                min.name = newName;
                            }

                            min.owner = remapper.map(min.owner);
                            min.desc = remapper.mapMethodDesc(min.desc);
                        } else if (insn instanceof InvokeDynamicInsnNode indy) {
                            // HANDLE INVOKEDYNAMIC (Lambdas)
                            // 1. Remap the name (though often arbitrary for lambdas)
                            String newName = remapper.mapInvokeDynamicMethodName(indy.name, indy.desc);
                            if (newName != null) {
                                indy.name = newName;
                            }

                            // 2. Remap the descriptor
                            indy.desc = remapper.mapMethodDesc(indy.desc);

                            // 3. Remap the Bootstrap Method Handle (BSM)
                            indy.bsm = (org.objectweb.asm.Handle) remapper.mapValue(indy.bsm);

                            // 4. Remap BSM Arguments (This is critical for lambdas! contains ref to actual
                            // method)
                            for (int i = 0; i < indy.bsmArgs.length; i++) {
                                indy.bsmArgs[i] = remapper.mapValue(indy.bsmArgs[i]);
                            }
                        } else if (insn instanceof FieldInsnNode fin) {
                            // UPDATE NAME FIRST
                            String newName = context.getNewFieldName(fin.owner, fin.name, fin.desc);
                            if (newName != null) {
                                fin.name = newName;
                            }

                            fin.owner = remapper.map(fin.owner);
                            fin.desc = remapper.mapDesc(fin.desc);
                        } else if (insn instanceof TypeInsnNode tin) {
                            tin.desc = remapper.map(tin.desc);
                        } else if (insn instanceof MultiANewArrayInsnNode multi) {
                            // Handle Multi-dimensional Arrays
                            multi.desc = remapper.mapDesc(multi.desc);
                        } else if (insn instanceof LdcInsnNode ldc) {
                            // Use Remapper.mapValue() to handle Type (Object/Array), Handle, and
                            // ConstantDynamic
                            ldc.cst = remapper.mapValue(ldc.cst);
                        }
                    }
                }

                // Update try-catch blocks
                if (method.tryCatchBlocks != null) {
                    for (TryCatchBlockNode tcb : method.tryCatchBlocks) {
                        if (tcb.type != null) {
                            tcb.type = remapper.map(tcb.type);
                        }
                    }
                }
            }

            // Update inner classes
            if (classNode.innerClasses != null) {
                for (InnerClassNode icn : classNode.innerClasses) {
                    icn.name = remapper.map(icn.name);
                    if (icn.outerName != null) {
                        icn.outerName = remapper.map(icn.outerName);
                    }
                }
            }
        }
    }

    private String generateNewClassName(String oldName, TransformContext context) {
        // Keep package structure but rename class
        int lastSlash = oldName.lastIndexOf('/');
        String packagePath = lastSlash > 0
                ? context.getClassNameGenerator().generatePackagePath(oldName.substring(0, lastSlash)) + "/"
                : "";
        String simpleName = context.getClassNameGenerator().generateClassName(oldName);

        return packagePath + simpleName;
    }

    private boolean isBukkitPlugin = false;

    private boolean isPluginMainClass(ClassNode classNode) {
        // Check if extends JavaPlugin or its variants
        if (classNode.superName != null) {
            String superName = classNode.superName;
            return superName.equals("org/bukkit/plugin/java/JavaPlugin") ||
                    superName.contains("JavaPlugin");
        }
        return false;
    }

    private boolean shouldRenameClass(ClassNode classNode) {
        // IMPORTANT: Don't rename ANY classes in Bukkit plugins
        // Because main class is excluded from obfuscation and still uses original names
        // If we rename other classes, main class can't find them ->
        // ClassNotFoundException
        // UPDATE: We now DO rename classes, because we don't exclude Main Class
        // anymore.
        /*
         * if (isBukkitPlugin) {
         * return false;
         * }
         */

        // Don't rename enums (can cause issues)
        if ((classNode.access & org.objectweb.asm.Opcodes.ACC_ENUM) != 0) {
            return false;
        }

        // Don't rename annotation types
        if ((classNode.access & org.objectweb.asm.Opcodes.ACC_ANNOTATION) != 0) {
            return false;
        }

        return true;
    }

    /**
     * Check if this is a Bukkit plugin (called from transform to set flag)
     */
    public void checkIfBukkitPlugin(TransformContext context) {
        isBukkitPlugin = context.getResourceEntries().containsKey("plugin.yml");
        if (isBukkitPlugin) {
            context.log("[INFO] Bukkit plugin detected - identifier renaming ENABLED");
            // context.log("[INFO] Bukkit plugin detected - identifier renaming DISABLED for
            // compatibility");
        }
    }

    private boolean shouldRenameMethod(ClassNode owner, MethodNode method) {
        // IMPORTANT: Don't rename methods in Bukkit plugins
        // Main class is not obfuscated and still uses original method names
        // UPDATE: We now allow renaming as long as it's not the Main Class
        /*
         * if (isBukkitPlugin) {
         * return false;
         * }
         */

        // Never rename constructors or static initializers
        if (method.name.startsWith("<")) {
            return false;
        }

        // Check if method should be kept based on config
        if (config.shouldKeepMethodName(method.name)) {
            return false;
        }

        // Check if in KEEP_METHODS set
        if (KEEP_METHODS.contains(method.name)) {
            return false;
        }

        // Check for keep annotations
        if (method.visibleAnnotations != null) {
            for (AnnotationNode ann : method.visibleAnnotations) {
                if (KEEP_ANNOTATIONS.contains(ann.desc)) {
                    return false;
                }
            }
        }

        // Don't rename overridden methods from Object
        if (isObjectMethod(method.name, method.desc)) {
            return false;
        }

        // Don't rename if it might be overriding an API method
        if (mightBeOverridingApiMethod(owner, method)) {
            return false;
        }

        return true;
    }

    private boolean shouldRenameField(ClassNode owner, FieldNode field) {
        // IMPORTANT: Don't rename fields in Bukkit plugins
        // Main class is not obfuscated and still uses original field names
        // UPDATE: We now allow renaming as long as it's not the Main Class
        /*
         * if (isBukkitPlugin) {
         * return false;
         * }
         */

        // Don't rename serialVersionUID
        if (field.name.equals("serialVersionUID")) {
            return false;
        }

        // Don't rename enum values
        if ((owner.access & org.objectweb.asm.Opcodes.ACC_ENUM) != 0 &&
                (field.access & org.objectweb.asm.Opcodes.ACC_ENUM) != 0) {
            return false;
        }

        return true;
    }

    private boolean isObjectMethod(String name, String desc) {
        return (name.equals("toString") && desc.equals("()Ljava/lang/String;")) ||
                (name.equals("hashCode") && desc.equals("()I")) ||
                (name.equals("equals") && desc.equals("(Ljava/lang/Object;)Z")) ||
                (name.equals("clone") && desc.equals("()Ljava/lang/Object;"));
    }

    private boolean mightBeOverridingApiMethod(ClassNode owner, MethodNode method) {
        // If class implements Bukkit interfaces, be careful
        if (owner.interfaces != null) {
            for (String iface : owner.interfaces) {
                if (iface.startsWith("org/bukkit/") ||
                        iface.startsWith("net/md_5/") ||
                        iface.startsWith("io/papermc/")) {
                    // This class implements a Bukkit interface
                    // Keep public/protected methods as they might be overrides
                    if ((method.access & org.objectweb.asm.Opcodes.ACC_PRIVATE) == 0) {
                        return true;
                    }
                }
            }
        }

        // If class extends a non-Object class, be careful with overrides
        if (owner.superName != null && !owner.superName.equals("java/lang/Object")) {
            if (owner.superName.startsWith("org/bukkit/") ||
                    owner.superName.startsWith("net/md_5/") ||
                    owner.superName.startsWith("io/papermc/")) {
                // Keep public/protected methods
                if ((method.access & org.objectweb.asm.Opcodes.ACC_PRIVATE) == 0) {
                    return true;
                }
            }
        }

        return false;
    }
}
