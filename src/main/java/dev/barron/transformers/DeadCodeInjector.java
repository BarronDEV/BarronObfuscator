package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import dev.barron.utils.RandomizationEngine;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Extreme Dead Code Injector with high randomization
 * 
 * Every obfuscation run produces vastly different dead code,
 * making pattern-based detection and removal nearly impossible.
 * 
 * Randomization includes:
 * - Random method count (2-15)
 * - Random field count (3-12)
 * - Random complexity per method (5-25 instructions)
 * - Random instruction patterns (12 different types)
 * - Random naming strategies
 */
public class DeadCodeInjector implements Transformer {

    private ObfuscationConfig config;
    private SecureRandom random;
    private RandomizationEngine randomEngine;

    // Fake method names - regenerated each session
    private final List<String> fakeMethodNames = new ArrayList<>();
    private final List<String> fakeFieldNames = new ArrayList<>();

    // Name generation strategies
    private final String[][] nameStrategies = {
            { "a", "b", "c", "d", "e", "f", "g", "h" },
            { "I", "l", "1", "O", "0" },
            { "_", "__", "___", "____" },
            { "λ", "α", "β", "γ", "δ" },
            { "m", "n", "o", "p", "q" },
            { "$", "$$", "$$$" },
            { "do", "if", "go", "to" }, // Short keywords that confuse
    };

    @Override
    public String getName() {
        return "Extreme Dead Code Injector";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
        this.random = new SecureRandom();

        // Generate random method and field names for this session
        generateRandomNames();
    }

    private void generateRandomNames() {
        fakeMethodNames.clear();
        fakeFieldNames.clear();

        // Random count of names to generate (10-30)
        int nameCount = random.nextInt(20) + 10;

        for (int i = 0; i < nameCount; i++) {
            // Random strategy selection
            String[] strategy = nameStrategies[random.nextInt(nameStrategies.length)];
            StringBuilder name = new StringBuilder();

            // Random length (1-5)
            int length = random.nextInt(5) + 1;
            for (int j = 0; j < length; j++) {
                name.append(strategy[random.nextInt(strategy.length)]);
            }

            // Add random suffix
            name.append(random.nextInt(10000));

            fakeMethodNames.add(name.toString());
            fakeFieldNames.add("f" + name);
        }
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;
        this.randomEngine = context.getRandomEngine();

        // Track used names for this class to prevent duplicates
        Set<String> usedNames = new HashSet<>();
        for (MethodNode mn : classNode.methods) {
            usedNames.add(mn.name);
        }

        // EXTREME RANDOMIZATION: Method count (2-15)
        int methodCount = randomEngine.getRandomInt(2, 15);

        for (int i = 0; i < methodCount; i++) {
            MethodNode fakeMethod = generateExtremelyRandomMethod(classNode, usedNames);
            if (fakeMethod != null) {
                classNode.methods.add(fakeMethod);
                usedNames.add(fakeMethod.name);
                context.incrementDeadCodeInjected();
                modified = true;
            }
        }

        // Track used field names
        Set<String> usedFieldNames = new HashSet<>();
        for (FieldNode fn : classNode.fields) {
            usedFieldNames.add(fn.name);
        }

        // EXTREME RANDOMIZATION: Field count (3-12)
        int fieldCount = randomEngine.getRandomInt(3, 12);

        for (int i = 0; i < fieldCount; i++) {
            FieldNode fakeField = generateExtremelyRandomField(usedFieldNames);
            if (fakeField != null) {
                classNode.fields.add(fakeField);
                usedFieldNames.add(fakeField.name);
                modified = true;
            }
        }

        // EXTREME RANDOMIZATION: Inner class-like structures (0-3)
        int innerCount = randomEngine.getRandomInt(0, 3);
        for (int i = 0; i < innerCount; i++) {
            addFakeInnerClassReference(classNode);
        }

        return modified;
    }

    /**
     * Generate extremely randomized fake method
     */
    private MethodNode generateExtremelyRandomMethod(ClassNode owner, Set<String> usedNames) {
        // Random name from pool - ensure uniqueness
        String name;
        int attempts = 0;
        do {
            name = fakeMethodNames.get(random.nextInt(fakeMethodNames.size()));
            attempts++;
            if (attempts > 50)
                return null; // Give up if can't find unique name
        } while (usedNames.contains(name));

        // Random access modifier combinations
        int access = Opcodes.ACC_PRIVATE;
        if (random.nextFloat() < 0.4)
            access |= Opcodes.ACC_STATIC;
        if (random.nextFloat() < 0.2)
            access |= Opcodes.ACC_FINAL;
        if (random.nextFloat() < 0.1)
            access |= Opcodes.ACC_SYNCHRONIZED;
        if (random.nextFloat() < 0.1)
            access |= Opcodes.ACC_SYNTHETIC;

        // Random return type from wider pool (void is allowed for return)
        String returnType = getRandomReturnType();

        // Random parameters (0-5) - void NOT allowed for params
        StringBuilder params = new StringBuilder();
        int paramCount = random.nextInt(6);
        for (int i = 0; i < paramCount; i++) {
            params.append(getRandomParamType());
        }

        String desc = "(" + params + ")" + returnType;

        MethodNode method = new MethodNode(access, name, desc, null, null);

        // EXTREME complexity - random between 5-25 instructions
        int complexity = randomEngine.getRandomInt(5, 25);
        method.instructions = generateExtremeMethodBody(returnType, complexity);
        method.maxStack = 10;
        method.maxLocals = paramCount + 10;

        return method;
    }

    /**
     * Get random type for PARAMETERS (void NOT allowed)
     */
    private String getRandomParamType() {
        return switch (random.nextInt(11)) {
            case 0 -> "I";
            case 1 -> "Z";
            case 2 -> "J";
            case 3 -> "D";
            case 4 -> "F";
            case 5 -> "B";
            case 6 -> "S";
            case 7 -> "C";
            case 8 -> "Ljava/lang/String;";
            case 9 -> "Ljava/lang/Object;";
            default -> "[I";
        };
    }

    /**
     * Get random type for RETURN (void IS allowed)
     */
    private String getRandomReturnType() {
        return switch (random.nextInt(12)) {
            case 0 -> "V";
            case 1 -> "I";
            case 2 -> "Z";
            case 3 -> "J";
            case 4 -> "D";
            case 5 -> "F";
            case 6 -> "B";
            case 7 -> "S";
            case 8 -> "C";
            case 9 -> "Ljava/lang/String;";
            case 10 -> "Ljava/lang/Object;";
            default -> "[I";
        };
    }

    /**
     * Generate extremely randomized method body
     */
    private InsnList generateExtremeMethodBody(String returnType, int complexity) {
        InsnList list = new InsnList();

        for (int i = 0; i < complexity; i++) {
            // 12 different instruction types for maximum variance
            switch (random.nextInt(12)) {
                case 0 -> {
                    // Random integer constant
                    int value = randomEngine.getRandomInt(-1000, 1000);
                    list.add(new LdcInsnNode(value));
                    list.add(new VarInsnNode(Opcodes.ISTORE, random.nextInt(5) + 1));
                }
                case 1 -> {
                    // Complex math
                    list.add(new LdcInsnNode(randomEngine.getRandomInt(1, 1000)));
                    list.add(new LdcInsnNode(randomEngine.getRandomInt(1, 1000)));
                    list.add(new InsnNode(random.nextBoolean() ? Opcodes.IMUL : Opcodes.IADD));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 2 -> {
                    // Random string with random content
                    String str = generateRandomString(randomEngine.getRandomInt(5, 30));
                    list.add(new LdcInsnNode(str));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 3 -> {
                    // Conditional with random opaque predicate
                    LabelNode label = new LabelNode();
                    long magic = randomEngine.getRandomMagicNumber();
                    list.add(new LdcInsnNode(magic));
                    list.add(new LdcInsnNode(magic + 1));
                    list.add(new InsnNode(Opcodes.LCMP));
                    list.add(new JumpInsnNode(Opcodes.IFGE, label));
                    // Dead code
                    list.add(new InsnNode(Opcodes.ICONST_0));
                    list.add(new InsnNode(Opcodes.POP));
                    list.add(label);
                }
                case 4 -> {
                    // Method call
                    list.add(new MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            "java/lang/System",
                            random.nextBoolean() ? "currentTimeMillis" : "nanoTime",
                            "()J",
                            false));
                    list.add(new InsnNode(Opcodes.POP2));
                }
                case 5 -> {
                    // Array creation with random size
                    int size = randomEngine.getRandomInt(1, 100);
                    list.add(new LdcInsnNode(size));
                    list.add(new IntInsnNode(Opcodes.NEWARRAY,
                            random.nextBoolean() ? Opcodes.T_INT : Opcodes.T_BYTE));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 6 -> {
                    // Long constant with random value
                    long value = randomEngine.getRandomMagicNumber();
                    list.add(new LdcInsnNode(value));
                    list.add(new VarInsnNode(Opcodes.LSTORE, random.nextInt(3) + 1));
                }
                case 7 -> {
                    // Double constant with random value
                    double value = random.nextDouble() * 1000000;
                    list.add(new LdcInsnNode(value));
                    list.add(new InsnNode(Opcodes.POP2));
                }
                case 8 -> {
                    // Nested loop structure (never executed)
                    LabelNode outer = new LabelNode();
                    LabelNode end = new LabelNode();
                    list.add(new InsnNode(Opcodes.ICONST_0));
                    list.add(new JumpInsnNode(Opcodes.IFEQ, end));
                    list.add(outer);
                    list.add(new InsnNode(Opcodes.NOP));
                    list.add(new JumpInsnNode(Opcodes.GOTO, outer));
                    list.add(end);
                }
                case 9 -> {
                    // Switch-like pattern
                    int cases = randomEngine.getRandomInt(2, 5);
                    list.add(new LdcInsnNode(random.nextInt(100)));
                    for (int c = 0; c < cases; c++) {
                        LabelNode skip = new LabelNode();
                        list.add(new InsnNode(Opcodes.DUP));
                        list.add(new LdcInsnNode(c));
                        list.add(new JumpInsnNode(Opcodes.IF_ICMPNE, skip));
                        list.add(new InsnNode(Opcodes.NOP));
                        list.add(skip);
                    }
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 10 -> {
                    // String builder pattern (fake)
                    list.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                    list.add(new InsnNode(Opcodes.DUP));
                    list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                            "java/lang/StringBuilder", "<init>", "()V", false));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 11 -> {
                    // Object array with random class
                    String[] classes = {
                            "java/lang/Object",
                            "java/lang/String",
                            "java/lang/Integer",
                            "java/util/ArrayList"
                    };
                    list.add(new LdcInsnNode(randomEngine.getRandomInt(1, 20)));
                    list.add(new TypeInsnNode(Opcodes.ANEWARRAY,
                            classes[random.nextInt(classes.length)]));
                    list.add(new InsnNode(Opcodes.POP));
                }
            }
        }

        // Random return
        addRandomReturn(list, returnType);

        return list;
    }

    /**
     * Generate random string with random characters
     */
    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            // Mix of readable and confusing characters
            if (random.nextFloat() < 0.7) {
                sb.append((char) ('a' + random.nextInt(26)));
            } else {
                // Unicode characters
                sb.append((char) (0x0400 + random.nextInt(100)));
            }
        }
        return sb.toString();
    }

    /**
     * Add appropriate return instruction
     */
    private void addRandomReturn(InsnList list, String returnType) {
        switch (returnType.charAt(0)) {
            case 'V' -> list.add(new InsnNode(Opcodes.RETURN));
            case 'I', 'Z', 'B', 'C', 'S' -> {
                list.add(new LdcInsnNode(randomEngine.getRandomInt(-100, 100)));
                list.add(new InsnNode(Opcodes.IRETURN));
            }
            case 'J' -> {
                list.add(new LdcInsnNode(randomEngine.getRandomMagicNumber()));
                list.add(new InsnNode(Opcodes.LRETURN));
            }
            case 'F' -> {
                list.add(new LdcInsnNode((float) random.nextDouble() * 100));
                list.add(new InsnNode(Opcodes.FRETURN));
            }
            case 'D' -> {
                list.add(new LdcInsnNode(random.nextDouble() * 1000));
                list.add(new InsnNode(Opcodes.DRETURN));
            }
            default -> {
                list.add(new InsnNode(Opcodes.ACONST_NULL));
                list.add(new InsnNode(Opcodes.ARETURN));
            }
        }
    }

    /**
     * Generate extremely randomized fake field
     */
    private FieldNode generateExtremelyRandomField(Set<String> usedNames) {
        String name;
        int attempts = 0;
        do {
            name = fakeFieldNames.get(random.nextInt(fakeFieldNames.size()));
            attempts++;
            if (attempts > 50) return null;
        } while (usedNames.contains(name));

        int access = Opcodes.ACC_PRIVATE;
        if (random.nextFloat() < 0.3)
            access |= Opcodes.ACC_STATIC;
        if (random.nextFloat() < 0.2)
            access |= Opcodes.ACC_FINAL;
        if (random.nextFloat() < 0.3)
            access |= Opcodes.ACC_TRANSIENT;
        if (random.nextFloat() < 0.1)
            access |= Opcodes.ACC_VOLATILE;
        if (random.nextFloat() < 0.1)
            access |= Opcodes.ACC_SYNTHETIC;

        // Use param type for fields (void not allowed)
        String desc = getRandomParamType();

        // Random initial value for some types
        Object value = null;
        if ((access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0) {
            value = switch (desc.charAt(0)) {
                case 'I' -> randomEngine.getRandomInt(-10000, 10000);
                case 'J' -> randomEngine.getRandomMagicNumber();
                case 'F' -> (float) random.nextDouble() * 100;
                case 'D' -> random.nextDouble() * 1000;
                default -> null;
            };
        }

        return new FieldNode(access, name, desc, null, value);
    }

    /**
     * Add fake inner class reference
     */
    private void addFakeInnerClassReference(ClassNode classNode) {
        String innerName = classNode.name + "$" + randomEngine.getRandomInt(1, 100);

        InnerClassNode innerClass = new InnerClassNode(
                innerName,
                classNode.name,
                Integer.toString(random.nextInt(10)),
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC);

        if (classNode.innerClasses == null) {
            classNode.innerClasses = new ArrayList<>();
        }
        classNode.innerClasses.add(innerClass);
    }
}
