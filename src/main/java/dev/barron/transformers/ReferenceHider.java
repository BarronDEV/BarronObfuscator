package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Reference Hiding Transformer
 * 
 * Hides method references and class references using:
 * - Reflection-based invocation for static methods
 * - Encrypted class/method names
 * - Dynamic method lookup
 * 
 * This makes static analysis extremely difficult as decompilers
 * cannot easily follow method calls.
 */
public class ReferenceHider implements Transformer {

    private ObfuscationConfig config;
    private final SecureRandom random = new SecureRandom();

    // Helper class for reflection calls
    private String helperClassName;

    @Override
    public String getName() {
        return "Reference Hider";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        // Generate unique helper class name for this session
        if (helperClassName == null) {
            String pkg = "a/a/b/" + generateRandomPackage();
            helperClassName = pkg + "/" + context.getClassNameGenerator().generateClassName("R");
        }

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null)
                continue;

            // Skip constructors and static initializers
            if (method.name.startsWith("<"))
                continue;

            // Skip huge methods to prevent 'Method too large' JVM limitation
            if (method.instructions.size() > 5000)
                continue;

            for (AbstractInsnNode insn : method.instructions.toArray()) {
                // Hide static method invocations
                if (insn instanceof MethodInsnNode methodInsn) {
                    if (methodInsn.getOpcode() == Opcodes.INVOKESTATIC) {
                        // Only hide calls to our own classes (not library calls)
                        if (context.isTargetClass(methodInsn.owner)) {
                            // ~30% chance to hide this call
                            if (random.nextFloat() < 0.3) {
                                modified |= hideStaticMethodCall(method, methodInsn, context);
                            }
                        }
                    }
                }

                // Hide field accesses
                if (insn instanceof FieldInsnNode fieldInsn) {
                    if (fieldInsn.getOpcode() == Opcodes.GETSTATIC) {
                        if (context.isTargetClass(fieldInsn.owner)) {
                            // ~20% chance to hide this access
                            if (random.nextFloat() < 0.2) {
                                modified |= hideStaticFieldAccess(method, fieldInsn, context);
                            }
                        }
                    }
                }
            }
        }

        return modified;
    }

    @Override
    public void finish(TransformContext context) {
        // Generate the reflection helper class
        if (helperClassName != null) {
            byte[] helperBytecode = generateHelperClass();
            context.addAdditionalClass(helperClassName, helperBytecode);
            context.logInfo("Generated reference helper class: " + helperClassName);
        }
    }

    private String generateRandomPackage() {
        String[] chars = { "a", "b", "c", "I", "l", "O" };
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            sb.append(chars[random.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    /**
     * Hide a static method call by converting it to reflection
     */
    private boolean hideStaticMethodCall(MethodNode method, MethodInsnNode methodInsn,
            TransformContext context) {

        // Parse the method descriptor to count arguments
        String desc = methodInsn.desc;
        int argCount = countArguments(desc);
        String returnType = getReturnType(desc);

        // For simplicity, only handle methods with 0-3 arguments
        if (argCount > 3) {
            return false;
        }

        InsnList replacement = new InsnList();

        // XOR-encrypt the class name
        // FIX: Use remapped name if available
        String owner = methodInsn.owner;
        String mappedOwner = context.getNewClassName(owner);
        String className = mappedOwner.replace("/", ".");

        int classKey = random.nextInt(256);
        int[] encryptedClass = encryptString(className, classKey);

        // XOR-encrypt the method name
        int methodKey = random.nextInt(256);
        int[] encryptedMethod = encryptString(methodInsn.name, methodKey);

        // If there are arguments on the stack, we need to save them
        // For simplicity, we'll use local variables

        int baseLocal = method.maxLocals;

        // Pop arguments into locals (in reverse order)
        List<String> argTypes = parseArgumentTypes(desc);
        for (int i = argTypes.size() - 1; i >= 0; i--) {
            String argType = argTypes.get(i);
            int storeOpcode = getStoreOpcode(argType);
            replacement.add(new VarInsnNode(storeOpcode, baseLocal + i));
        }

        // Call helper to get method handle and invoke
        // Helper.invoke(encryptedClass, classKey, encryptedMethod, methodKey, args...)

        // Push encrypted class name
        replacement.add(createIntArray(encryptedClass));
        replacement.add(createIntPush(classKey));

        // Push encrypted method name
        replacement.add(createIntArray(encryptedMethod));
        replacement.add(createIntPush(methodKey));

        // Push argument count
        replacement.add(createIntPush(argCount));

        // Create Object[] for arguments
        replacement.add(createIntPush(argCount));
        replacement.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));

        // Fill argument array
        for (int i = 0; i < argTypes.size(); i++) {
            replacement.add(new InsnNode(Opcodes.DUP));
            replacement.add(createIntPush(i));

            String argType = argTypes.get(i);
            int loadOpcode = getLoadOpcode(argType);
            replacement.add(new VarInsnNode(loadOpcode, baseLocal + i));

            // Box primitive if needed
            addBoxingInstruction(replacement, argType);

            replacement.add(new InsnNode(Opcodes.AASTORE));
        }

        // Call the helper's invoke method
        replacement.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                helperClassName,
                "i", // invoke
                "([II[II[Ljava/lang/Object;)Ljava/lang/Object;",
                false));

        // Unbox result if needed
        addUnboxingInstruction(replacement, returnType);

        method.instructions.insert(methodInsn, replacement);
        method.instructions.remove(methodInsn);

        method.maxLocals += argTypes.size() + 2;
        method.maxStack = Math.max(method.maxStack, 10);

        return true;
    }

    /**
     * Hide a static field access by converting it to reflection
     */
    private boolean hideStaticFieldAccess(MethodNode method, FieldInsnNode fieldInsn,
            TransformContext context) {

        InsnList replacement = new InsnList();

        // XOR-encrypt the class name
        // FIX: Use remapped name if available
        String owner = fieldInsn.owner;
        String mappedOwner = context.getNewClassName(owner);
        String className = mappedOwner.replace("/", ".");

        int classKey = random.nextInt(256);
        int[] encryptedClass = encryptString(className, classKey);

        // XOR-encrypt the field name
        int fieldKey = random.nextInt(256);
        int[] encryptedField = encryptString(fieldInsn.name, fieldKey);

        // Push encrypted class name
        replacement.add(createIntArray(encryptedClass));
        replacement.add(createIntPush(classKey));

        // Push encrypted field name
        replacement.add(createIntArray(encryptedField));
        replacement.add(createIntPush(fieldKey));

        // Call helper's field get method
        replacement.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                helperClassName,
                "f", // field
                "([II[II)Ljava/lang/Object;",
                false));

        // Unbox/cast result
        addUnboxingInstruction(replacement, fieldInsn.desc);

        method.instructions.insert(fieldInsn, replacement);
        method.instructions.remove(fieldInsn);

        method.maxStack = Math.max(method.maxStack, 8);

        return true;
    }

    /**
     * Simple XOR encryption for strings
     */
    private int[] encryptString(String str, int key) {
        byte[] bytes = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int[] result = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = (bytes[i] ^ key ^ i) & 0xFF;
        }
        return result;
    }

    /**
     * Create bytecode to push an int array
     */
    private InsnList createIntArray(int[] values) {
        InsnList list = new InsnList();
        list.add(createIntPush(values.length));
        list.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));

        for (int i = 0; i < values.length; i++) {
            list.add(new InsnNode(Opcodes.DUP));
            list.add(createIntPush(i));
            list.add(createIntPush(values[i]));
            list.add(new InsnNode(Opcodes.IASTORE));
        }

        return list;
    }

    private AbstractInsnNode createIntPush(int value) {
        if (value >= -1 && value <= 5) {
            return new InsnNode(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            return new IntInsnNode(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            return new IntInsnNode(Opcodes.SIPUSH, value);
        } else {
            return new LdcInsnNode(value);
        }
    }

    private int countArguments(String desc) {
        int count = 0;
        int i = 1; // Skip '('
        while (desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'L') {
                while (desc.charAt(i) != ';')
                    i++;
            } else if (c == '[') {
                i++;
                continue;
            }
            count++;
            i++;
        }
        return count;
    }

    private String getReturnType(String desc) {
        int i = desc.indexOf(')') + 1;
        return desc.substring(i);
    }

    private List<String> parseArgumentTypes(String desc) {
        List<String> types = new ArrayList<>();
        int i = 1; // Skip '('
        while (desc.charAt(i) != ')') {
            int start = i;
            char c = desc.charAt(i);
            if (c == 'L') {
                while (desc.charAt(i) != ';')
                    i++;
                i++;
            } else if (c == '[') {
                i++;
                if (desc.charAt(i) == 'L') {
                    while (desc.charAt(i) != ';')
                        i++;
                    i++;
                } else {
                    i++;
                }
            } else {
                i++;
            }
            types.add(desc.substring(start, i));
        }
        return types;
    }

    private int getStoreOpcode(String type) {
        if (type.startsWith("L") || type.startsWith("["))
            return Opcodes.ASTORE;
        return switch (type.charAt(0)) {
            case 'I', 'B', 'C', 'S', 'Z' -> Opcodes.ISTORE;
            case 'J' -> Opcodes.LSTORE;
            case 'F' -> Opcodes.FSTORE;
            case 'D' -> Opcodes.DSTORE;
            default -> Opcodes.ASTORE;
        };
    }

    private int getLoadOpcode(String type) {
        if (type.startsWith("L") || type.startsWith("["))
            return Opcodes.ALOAD;
        return switch (type.charAt(0)) {
            case 'I', 'B', 'C', 'S', 'Z' -> Opcodes.ILOAD;
            case 'J' -> Opcodes.LLOAD;
            case 'F' -> Opcodes.FLOAD;
            case 'D' -> Opcodes.DLOAD;
            default -> Opcodes.ALOAD;
        };
    }

    private void addBoxingInstruction(InsnList list, String type) {
        if (type.startsWith("L") || type.startsWith("["))
            return;

        switch (type.charAt(0)) {
            case 'I' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
            case 'J' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
            case 'F' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
            case 'D' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
            case 'Z' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
            case 'B' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false));
            case 'C' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
            case 'S' -> list.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false));
        }
    }

    private void addUnboxingInstruction(InsnList list, String type) {
        if (type.equals("V")) {
            list.add(new InsnNode(Opcodes.POP));
            return;
        }

        if (type.startsWith("L")) {
            String internalName = type.substring(1, type.length() - 1);
            list.add(new TypeInsnNode(Opcodes.CHECKCAST, internalName));
            return;
        }

        if (type.startsWith("[")) {
            list.add(new TypeInsnNode(Opcodes.CHECKCAST, type));
            return;
        }

        switch (type.charAt(0)) {
            case 'I' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Integer", "intValue", "()I", false));
            }
            case 'J' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Long", "longValue", "()J", false));
            }
            case 'F' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Float", "floatValue", "()F", false));
            }
            case 'D' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Double", "doubleValue", "()D", false));
            }
            case 'Z' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Boolean", "booleanValue", "()Z", false));
            }
            case 'B' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Byte"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Byte", "byteValue", "()B", false));
            }
            case 'C' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Character", "charValue", "()C", false));
            }
            case 'S' -> {
                list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Short"));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Short", "shortValue", "()S", false));
            }
        }
    }

    /**
     * Generate the reflection helper class
     */
    private byte[] generateHelperClass() {
        ClassNode helper = new ClassNode();
        helper.version = Opcodes.V21;
        helper.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        helper.name = helperClassName;
        helper.superName = "java/lang/Object";

        // Add decrypt string method
        helper.methods.add(createDecryptMethod());

        // Add invoke method
        helper.methods.add(createInvokeMethod());

        // Add field access method
        helper.methods.add(createFieldMethod());

        org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
        helper.accept(cw);
        return cw.toByteArray();
    }

    /**
     * Create decrypt method: String s(int[] enc, int key)
     */
    private MethodNode createDecryptMethod() {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                "s",
                "([II)Ljava/lang/String;",
                null,
                null);

        InsnList insns = new InsnList();

        // byte[] result = new byte[enc.length];
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // for loop
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 3));

        LabelNode loopStart = new LabelNode();
        LabelNode loopEnd = new LabelNode();

        insns.add(loopStart);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // result[i] = (byte)(enc[i] ^ key ^ i);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2B));
        insns.add(new InsnNode(Opcodes.BASTORE));

        insns.add(new IincInsnNode(3, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

        insns.add(loopEnd);

        // return new String(result, UTF_8);
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8",
                "Ljava/nio/charset/Charset;"));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/String", "<init>",
                "([BLjava/nio/charset/Charset;)V", false));
        insns.add(new InsnNode(Opcodes.ARETURN));

        method.instructions = insns;
        method.maxStack = 5;
        method.maxLocals = 4;

        return method;
    }

    /**
     * Create invoke method: Object i(int[] encClass, int classKey, int[] encMethod,
     * int methodKey, Object[] args)
     */
    private MethodNode createInvokeMethod() {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "i",
                "([II[II[Ljava/lang/Object;)Ljava/lang/Object;",
                null,
                new String[] { "java/lang/Exception" });

        InsnList insns = new InsnList();

        // String className = s(encClass, classKey);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                helperClassName, "s", "([II)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // String methodName = s(encMethod, methodKey);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                helperClassName, "s", "([II)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 6));

        // Class<?> clazz = Class.forName(className);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 5));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 7));

        // Get methods and find matching one
        insns.add(new VarInsnNode(Opcodes.ALOAD, 7));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getDeclaredMethods",
                "()[Ljava/lang/reflect/Method;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 8));

        // Loop through methods
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 9));

        LabelNode loopStart = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        LabelNode continueLabel = new LabelNode();

        insns.add(loopStart);
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 8));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // Method m = methods[i];
        insns.add(new VarInsnNode(Opcodes.ALOAD, 8));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 10));

        // if (m.getName().equals(methodName))
        insns.add(new VarInsnNode(Opcodes.ALOAD, 10));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Method", "getName",
                "()Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 6));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "equals",
                "(Ljava/lang/Object;)Z", false));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, continueLabel));

        // m.setAccessible(true);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 10));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Method", "setAccessible",
                "(Z)V", false));

        // return m.invoke(null, args);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 10));
        insns.add(new InsnNode(Opcodes.ACONST_NULL));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 4));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.ARETURN));

        insns.add(continueLabel);
        insns.add(new IincInsnNode(9, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

        insns.add(loopEnd);

        // return null;
        insns.add(new InsnNode(Opcodes.ACONST_NULL));
        insns.add(new InsnNode(Opcodes.ARETURN));

        method.instructions = insns;
        method.maxStack = 6;
        method.maxLocals = 11;

        return method;
    }

    /**
     * Create field access method: Object f(int[] encClass, int classKey, int[]
     * encField, int fieldKey)
     */
    private MethodNode createFieldMethod() {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "f",
                "([II[II)Ljava/lang/Object;",
                null,
                new String[] { "java/lang/Exception" });

        InsnList insns = new InsnList();

        // String className = s(encClass, classKey);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                helperClassName, "s", "([II)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 4));

        // String fieldName = s(encField, fieldKey);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                helperClassName, "s", "([II)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // Class<?> clazz = Class.forName(className);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 4));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 6));

        // Field f = clazz.getDeclaredField(fieldName);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 6));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 5));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getDeclaredField",
                "(Ljava/lang/String;)Ljava/lang/reflect/Field;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 7));

        // f.setAccessible(true);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 7));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Field", "setAccessible",
                "(Z)V", false));

        // return f.get(null);
        insns.add(new VarInsnNode(Opcodes.ALOAD, 7));
        insns.add(new InsnNode(Opcodes.ACONST_NULL));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Field", "get",
                "(Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.ARETURN));

        method.instructions = insns;
        method.maxStack = 4;
        method.maxLocals = 8;

        return method;
    }
}
