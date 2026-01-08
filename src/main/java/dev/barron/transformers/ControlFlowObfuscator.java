package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Obfuscates control flow by adding fake branches, opaque predicates,
 * and restructuring code
 */
public class ControlFlowObfuscator implements Transformer {

    private ObfuscationConfig config;
    private final SecureRandom random = new SecureRandom();

    // Field name for opaque predicate
    private String opaqueFieldName;

    @Override
    public String getName() {
        return "Control Flow Obfuscator";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
        this.opaqueFieldName = "a" + random.nextInt(1000);
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        // Add opaque predicate field (always false but hard to analyze)
        addOpaqueField(classNode);

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null || method.instructions.size() < 5)
                continue;

            // Skip constructors and static initializers
            if (method.name.startsWith("<"))
                continue;

            // Add fake conditional jumps
            modified |= addFakeConditionals(classNode, method);

            // Add dead code blocks
            modified |= addDeadBranches(classNode, method);
        }

        return modified;
    }

    /**
     * Add a static field that's always false (opaque predicate)
     */
    private void addOpaqueField(ClassNode classNode) {
        // Check if field already exists
        for (FieldNode field : classNode.fields) {
            if (field.name.equals(opaqueFieldName))
                return;
        }

        FieldNode opaqueField = new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                opaqueFieldName,
                "Z",
                null,
                false);
        classNode.fields.add(opaqueField);
    }

    /**
     * Add fake conditional jumps that never execute
     */
    private boolean addFakeConditionals(ClassNode classNode, MethodNode method) {
        boolean modified = false;
        List<AbstractInsnNode> insertPoints = new ArrayList<>();

        // Find good insertion points (before some instructions)
        for (AbstractInsnNode insn : method.instructions) {
            if (insn.getOpcode() >= Opcodes.IRETURN && insn.getOpcode() <= Opcodes.RETURN)
                continue;
            if (insn instanceof LabelNode)
                continue;
            if (insn instanceof LineNumberNode)
                continue;
            if (insn instanceof FrameNode)
                continue;

            if (random.nextFloat() < 0.1) { // 10% chance to add fake conditional
                insertPoints.add(insn);
            }
        }

        for (AbstractInsnNode insertPoint : insertPoints) {
            InsnList fakeConditional = createFakeConditional(classNode);
            method.instructions.insertBefore(insertPoint, fakeConditional);
            modified = true;
        }

        return modified;
    }

    /**
     * Create a fake conditional that never executes
     */
    private InsnList createFakeConditional(ClassNode classNode) {
        InsnList list = new InsnList();
        LabelNode skipLabel = new LabelNode();

        // Load opaque predicate (always false)
        list.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                classNode.name,
                opaqueFieldName,
                "Z"));

        // Jump if false (which is always)
        list.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));

        // Dead code (never executed)
        list.add(createDeadCodeBlock());

        list.add(skipLabel);

        return list;
    }

    /**
     * Add branches that lead to dead code
     */
    private boolean addDeadBranches(ClassNode classNode, MethodNode method) {
        // Find method entry point
        AbstractInsnNode first = method.instructions.getFirst();
        while (first != null
                && (first instanceof LabelNode || first instanceof LineNumberNode || first instanceof FrameNode)) {
            first = first.getNext();
        }

        if (first == null)
            return false;

        InsnList entryCheck = new InsnList();
        LabelNode continueLabel = new LabelNode();

        // More complex opaque predicate: (System.nanoTime() > 0) is always true
        // but adds method call complexity
        entryCheck.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false));
        entryCheck.add(new InsnNode(Opcodes.LCONST_0));
        entryCheck.add(new InsnNode(Opcodes.LCMP));
        entryCheck.add(new JumpInsnNode(Opcodes.IFGT, continueLabel));

        // Dead code path - never executed
        entryCheck.add(createDeadCodeBlock());

        // Throw to satisfy verifier (unreachable)
        entryCheck.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
        entryCheck.add(new InsnNode(Opcodes.DUP));
        entryCheck.add(new MethodInsnNode(
                Opcodes.INVOKESPECIAL,
                "java/lang/RuntimeException",
                "<init>",
                "()V",
                false));
        entryCheck.add(new InsnNode(Opcodes.ATHROW));

        entryCheck.add(continueLabel);

        method.instructions.insertBefore(first, entryCheck);

        return true;
    }

    /**
     * Create a block of meaningless but valid bytecode
     */
    private InsnList createDeadCodeBlock() {
        InsnList list = new InsnList();

        int complexity = random.nextInt(3) + 1;

        for (int i = 0; i < complexity; i++) {
            switch (random.nextInt(4)) {
                case 0 -> {
                    // Push and pop
                    list.add(new InsnNode(Opcodes.ICONST_0));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 1 -> {
                    // Push two and pop
                    list.add(new InsnNode(Opcodes.ICONST_1));
                    list.add(new InsnNode(Opcodes.ICONST_2));
                    list.add(new InsnNode(Opcodes.POP2));
                }
                case 2 -> {
                    // Math operation
                    list.add(new InsnNode(Opcodes.ICONST_3));
                    list.add(new InsnNode(Opcodes.ICONST_4));
                    list.add(new InsnNode(Opcodes.IADD));
                    list.add(new InsnNode(Opcodes.POP));
                }
                case 3 -> {
                    // Load null and pop
                    list.add(new InsnNode(Opcodes.ACONST_NULL));
                    list.add(new InsnNode(Opcodes.POP));
                }
            }
        }

        return list;
    }
}
