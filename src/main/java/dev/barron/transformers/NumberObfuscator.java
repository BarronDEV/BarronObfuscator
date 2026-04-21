package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Obfuscates numeric constants by replacing them with complex expressions
 * Makes it harder to search for magic numbers
 */
public class NumberObfuscator implements Transformer {

    private ObfuscationConfig config;
    private final SecureRandom random = new SecureRandom();

    @Override
    public String getName() {
        return "Number Obfuscator";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        for (MethodNode method : classNode.methods) {
            if (method.instructions == null)
                continue;

            AbstractInsnNode[] instructions = method.instructions.toArray();
            for (AbstractInsnNode insn : instructions) {
                if (insn == null)
                    continue; // Safety check

                InsnList replacement = null;

                if (insn instanceof LdcInsnNode ldc) {
                    if (ldc.cst instanceof Integer i) {
                        replacement = obfuscateInt(i);
                    } else if (ldc.cst instanceof Long l) {
                        replacement = obfuscateLong(l);
                    }
                } else if (insn instanceof IntInsnNode iin) {
                    if (iin.getOpcode() == Opcodes.BIPUSH || iin.getOpcode() == Opcodes.SIPUSH) {
                        replacement = obfuscateInt(iin.operand);
                    }
                } else if (insn.getOpcode() >= Opcodes.ICONST_M1 && insn.getOpcode() <= Opcodes.ICONST_5) {
                    int value = insn.getOpcode() - Opcodes.ICONST_0;
                    // Only obfuscate some of these to avoid bloat
                    if (random.nextBoolean()) {
                        replacement = obfuscateInt(value);
                    }
                }

                if (replacement != null) {
                    method.instructions.insert(insn, replacement);
                    method.instructions.remove(insn);
                    modified = true;
                }
            }
        }

        return modified;
    }

    /**
     * Obfuscate an integer constant
     */
    private InsnList obfuscateInt(int value) {
        InsnList list = new InsnList();

        int strategy = random.nextInt(5);

        switch (strategy) {
            case 0 -> {
                // XOR: a ^ b = value
                int a = random.nextInt();
                int b = value ^ a;
                list.add(createIntPush(a));
                list.add(createIntPush(b));
                list.add(new InsnNode(Opcodes.IXOR));
            }
            case 1 -> {
                // Addition: a + b = value
                int a = random.nextInt(1000000) - 500000;
                int b = value - a;
                list.add(createIntPush(a));
                list.add(createIntPush(b));
                list.add(new InsnNode(Opcodes.IADD));
            }
            case 2 -> {
                // Subtraction: a - b = value
                int b = random.nextInt(1000000);
                int a = value + b;
                list.add(createIntPush(a));
                list.add(createIntPush(b));
                list.add(new InsnNode(Opcodes.ISUB));
            }
            case 3 -> {
                // Multiple operations: (a ^ b) + c = value
                int a = random.nextInt();
                int b = random.nextInt();
                int c = value - (a ^ b);
                list.add(createIntPush(a));
                list.add(createIntPush(b));
                list.add(new InsnNode(Opcodes.IXOR));
                list.add(createIntPush(c));
                list.add(new InsnNode(Opcodes.IADD));
            }
            case 4 -> {
                // Negation: -(-value)
                list.add(createIntPush(-value));
                list.add(new InsnNode(Opcodes.INEG));
            }
        }

        return list;
    }

    /**
     * Obfuscate a long constant
     */
    private InsnList obfuscateLong(long value) {
        InsnList list = new InsnList();

        int strategy = random.nextInt(3);

        switch (strategy) {
            case 0 -> {
                // XOR
                long a = random.nextLong();
                long b = value ^ a;
                list.add(new LdcInsnNode(a));
                list.add(new LdcInsnNode(b));
                list.add(new InsnNode(Opcodes.LXOR));
            }
            case 1 -> {
                // Addition
                long a = random.nextLong() & 0xFFFFFFFFL;
                long b = value - a;
                list.add(new LdcInsnNode(a));
                list.add(new LdcInsnNode(b));
                list.add(new InsnNode(Opcodes.LADD));
            }
            case 2 -> {
                // Negation
                list.add(new LdcInsnNode(-value));
                list.add(new InsnNode(Opcodes.LNEG));
            }
        }

        return list;
    }

    private AbstractInsnNode createIntPush(int value) {
        if (value == -1) {
            return new InsnNode(Opcodes.ICONST_M1);
        } else if (value >= 0 && value <= 5) {
            return new InsnNode(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            return new IntInsnNode(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            return new IntInsnNode(Opcodes.SIPUSH, value);
        } else {
            return new LdcInsnNode(value);
        }
    }
}
