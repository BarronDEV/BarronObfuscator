package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import dev.barron.vm.BarronOpCode;
import dev.barron.vm.BarronVM;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Transforms standard Java bytecode into BarronVM bytecode.
 * 
 * V1 Implementation:
 * - Supports basic Math (ADD, SUB, MUL, DIV)
 * - Supports basic Logic (EQ, JMP, RET)
 * - Supports static methods with Integer arguments/return only (MVP)
 */
public class VirtualizationTransformer implements Transformer {

    private ObfuscationConfig config;

    @Override
    public String getName() {
        return "BarronVM Virtualization";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        // Skip interfaces
        if ((classNode.access & Opcodes.ACC_INTERFACE) != 0)
            return false;

        boolean modified = false;

        for (MethodNode method : classNode.methods) {
            // MVP: Virtualize only static methods with int return/args to verify concept
            // Avoid constructors and too complex methods for V1
            if ((method.access & Opcodes.ACC_STATIC) == 0)
                continue;
            if (method.name.startsWith("<"))
                continue;
            if (!method.desc.endsWith("I") && !method.desc.endsWith("V"))
                continue;

            // Heuristic: Check if method is suitable for virtualization (simple logic/math)
            if (isVirtualizable(method)) {
                try {
                    virtualizeMethod(classNode, method);
                    context.logInfo("Virtualizing method: " + classNode.name + "." + method.name);
                    modified = true;
                } catch (Exception e) {
                    context.logInfo("Skipping virtualization for " + method.name + " due to: " + e.getMessage());
                }
            }
        }

        return modified;
    }

    private boolean isVirtualizable(MethodNode method) {
        // Simple check: only standard opcodes we support
        for (AbstractInsnNode insn : method.instructions) {
            int op = insn.getOpcode();
            if (op == -1)
                continue; // Label, LineNumber, etc.

            // Block unsupported instructions for MVP
            if (op == Opcodes.INVOKEVIRTUAL || op == Opcodes.INVOKEINTERFACE ||
                    op == Opcodes.GETFIELD || op == Opcodes.PUTFIELD ||
                    op == Opcodes.NEW || op == Opcodes.ATHROW) {
                return false;
            }
        }
        return true;
    }

    private void virtualizeMethod(ClassNode owner, MethodNode method) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);

        for (AbstractInsnNode insn : method.instructions) {
            int op = insn.getOpcode();
            if (op == -1)
                continue;

            switch (op) {
                case Opcodes.ICONST_M1 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(-1);
                }
                case Opcodes.ICONST_0 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(0);
                }
                case Opcodes.ICONST_1 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(1);
                }
                case Opcodes.ICONST_2 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(2);
                }
                case Opcodes.ICONST_3 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(3);
                }
                case Opcodes.ICONST_4 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(4);
                }
                case Opcodes.ICONST_5 -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(5);
                }

                case Opcodes.BIPUSH -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(((IntInsnNode) insn).operand);
                }
                case Opcodes.SIPUSH -> {
                    out.writeByte(BarronOpCode.PUSH);
                    out.writeInt(((IntInsnNode) insn).operand);
                }
                case Opcodes.LDC -> {
                    Object cst = ((LdcInsnNode) insn).cst;
                    if (cst instanceof Integer) {
                        out.writeByte(BarronOpCode.PUSH);
                        out.writeInt((Integer) cst);
                    } else {
                        throw new IllegalArgumentException("Unsupported LDC constant: " + cst.getClass());
                    }
                }

                case Opcodes.ILOAD -> {
                    out.writeByte(BarronOpCode.LOAD);
                    out.writeByte(((VarInsnNode) insn).var);
                }

                case Opcodes.IADD -> out.writeByte(BarronOpCode.ADD);
                case Opcodes.ISUB -> out.writeByte(BarronOpCode.SUB);
                case Opcodes.IMUL -> out.writeByte(BarronOpCode.MUL);
                case Opcodes.IDIV -> out.writeByte(BarronOpCode.DIV);
                case Opcodes.IXOR -> out.writeByte(BarronOpCode.XOR);

                case Opcodes.IRETURN -> out.writeByte(BarronOpCode.RET);
                case Opcodes.RETURN -> out.writeByte(BarronOpCode.RET_VOID);

                // Ignore unsupported for now (or throw to be safe)
                default -> throw new IllegalArgumentException("Unsupported opcode: " + op);
            }
        }

        byte[] vmCode = baos.toByteArray();

        // Clear original code
        method.instructions.clear();
        method.tryCatchBlocks.clear();
        method.localVariables = null;

        // Replace with: return (returnType) BarronVM.exec(vmCode, new Object[] {
        // args... });
        InsnList list = new InsnList();

        // 1. Push Code Array
        list.add(createByteArrayPush(vmCode));

        // 2. Push Locals Array
        int paramCount = Type.getArgumentTypes(method.desc).length;
        list.add(createIntPush(paramCount));
        list.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));

        // Fill locals
        int varIndex = 0;
        Type[] args = Type.getArgumentTypes(method.desc);
        for (int i = 0; i < args.length; i++) {
            list.add(new InsnNode(Opcodes.DUP));
            list.add(createIntPush(i));

            // Load Arg
            if (args[i].getSort() == Type.INT) {
                list.add(new VarInsnNode(Opcodes.ILOAD, varIndex));
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                        "(I)Ljava/lang/Integer;", false));
                varIndex++;
            } else {
                throw new IllegalStateException("Only INT args supported in V1");
            }

            list.add(new InsnNode(Opcodes.AASTORE));
        }

        // 3. Invoke BarronVM.exec
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "dev/barron/vm/BarronVM",
                "exec",
                "([B[Ljava/lang/Object;)Ljava/lang/Object;",
                false));

        // 4. Return result
        if (method.desc.endsWith("V")) {
            list.add(new InsnNode(Opcodes.POP)); // Pop null result
            list.add(new InsnNode(Opcodes.RETURN));
        } else {
            // Unbox Integer
            list.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
            list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false));
            list.add(new InsnNode(Opcodes.IRETURN));
        }

        method.instructions.add(list);
        method.maxStack = 8;
        method.maxLocals = varIndex + 2;
    }

    private AbstractInsnNode createIntPush(int value) {
        if (value >= -1 && value <= 5)
            return new InsnNode(Opcodes.ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE)
            return new IntInsnNode(Opcodes.BIPUSH, value);
        return new LdcInsnNode(value);
    }

    private InsnList createByteArrayPush(byte[] data) {
        InsnList list = new InsnList();
        list.add(createIntPush(data.length));
        list.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < data.length; i++) {
            list.add(new InsnNode(Opcodes.DUP));
            list.add(createIntPush(i));
            list.add(createIntPush(data[i]));
            list.add(new InsnNode(Opcodes.BASTORE));
        }
        return list;
    }
}
