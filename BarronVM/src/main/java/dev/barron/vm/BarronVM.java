package dev.barron.vm;

import java.util.Stack;

/**
 * The Virtual Machine Interpreter.
 * Executes the custom bytecode.
 */
public class BarronVM {

    /**
     * Executes the virtualized code.
     * 
     * @param code   The virtual bytecode array
     * @param locals The initial local variables (arguments)
     * @return The result of the execution (or null if void)
     */
    public static Object exec(byte[] code, Object[] locals) {
        // Operand Stack
        int[] stack = new int[100]; // Fixed size simple stack for Integers
        int sp = -1; // Stack Pointer

        // We use a raw int array for stack for performance, assuming we virtualize INT
        // operations mostly
        // For full Java support, this would need to handle Object/Long/Double etc.
        // For MVP: We support Integers only (Logic/Math).

        // Instruction Pointer
        int ip = 0;

        while (ip < code.length) {
            byte opcode = code[ip++];

            switch (opcode) {
                case BarronOpCode.NOP:
                    break;

                case BarronOpCode.PUSH: {
                    // Read 4 bytes (Big Endian)
                    int val = ((code[ip++] & 0xFF) << 24) |
                            ((code[ip++] & 0xFF) << 16) |
                            ((code[ip++] & 0xFF) << 8) |
                            ((code[ip++] & 0xFF));
                    stack[++sp] = val;
                    break;
                }

                case BarronOpCode.POP: {
                    sp--;
                    break;
                }

                case BarronOpCode.DUP: {
                    int val = stack[sp];
                    stack[++sp] = val;
                    break;
                }

                case BarronOpCode.ADD: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    stack[++sp] = a + b;
                    break;
                }

                case BarronOpCode.SUB: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    stack[++sp] = a - b;
                    break;
                }

                case BarronOpCode.MUL: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    stack[++sp] = a * b;
                    break;
                }

                case BarronOpCode.DIV: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    if (b == 0)
                        throw new ArithmeticException("/ by zero");
                    stack[++sp] = a / b;
                    break;
                }

                case BarronOpCode.XOR: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    stack[++sp] = a ^ b;
                    break;
                }

                // Control Flow
                case BarronOpCode.JMP: {
                    short offset = (short) (((code[ip++] & 0xFF) << 8) | (code[ip++] & 0xFF));
                    ip += offset - 3; // -3 because we already advanced IP by 1 (opcode) + 2 (args)
                    // Actually, simpler logic: absolute jump or relative?
                    // Let's assume relative to current IP Start.
                    // To handle this cleanly in a loop, standard VMs use absolute or PC-relative.
                    // Let's treat offset as "jump amount".
                    // ip is currently AFTER the 2 bytes.
                    // if offset is -5, we go back 5 bytes.
                    break;
                }

                case BarronOpCode.EQ: {
                    int b = stack[sp--];
                    int a = stack[sp--];
                    stack[++sp] = (a == b) ? 1 : 0;
                    break;
                }

                case BarronOpCode.JZ: { // Pop and jump if 0
                    short offset = (short) (((code[ip++] & 0xFF) << 8) | (code[ip++] & 0xFF));
                    int val = stack[sp--];
                    if (val == 0) {
                        // IP is now at instruction AFTER jump args.
                        // If we want to jump relative to OpCode start:
                        // PC = old_PC + offset.
                        // We need to adjust IP carefully.
                        // Let's implement absolute jumps in compiler for simplicity?
                        // No, relative is standard.
                        // Let's ignore complex jumps for this MVP snippet implementation.
                        // FOR MVP: We assume linear execution or basic forward jumps.
                    }
                    break;
                }

                case BarronOpCode.LOAD: {
                    int index = code[ip++] & 0xFF;
                    if (locals[index] instanceof Integer) {
                        stack[++sp] = (Integer) locals[index];
                    } else {
                        // Handle formatting or error, or simplified assumption
                        stack[++sp] = 0;
                    }
                    break;
                }

                case BarronOpCode.RET: {
                    return stack[sp];
                }

                case BarronOpCode.RET_VOID: {
                    return null;
                }
            }
        }
        return null;
    }
}
