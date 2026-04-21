package dev.barron.vm;

/**
 * Instruction Set for BarronVM.
 * These are the bytecodes that the VM understands.
 */
public class BarronOpCode {
    // Stack Operations
    public static final byte NOP = 0x00;
    public static final byte PUSH = 0x01; // Followed by Int (4 bytes)
    public static final byte POP = 0x02;
    public static final byte DUP = 0x03;
    public static final byte SWAP = 0x04;

    // Arithmetic
    public static final byte ADD = 0x10;
    public static final byte SUB = 0x11;
    public static final byte MUL = 0x12;
    public static final byte DIV = 0x13;
    public static final byte REM = 0x14;
    public static final byte NEG = 0x15;

    // Bitwise
    public static final byte SHL = 0x20;
    public static final byte SHR = 0x21;
    public static final byte USHR = 0x22;
    public static final byte AND = 0x23;
    public static final byte OR = 0x24;
    public static final byte XOR = 0x25;

    // Logic / Jumps
    public static final byte JMP = 0x30; // Followed by Offset (2 bytes)
    public static final byte JZ = 0x31; // Jump if Zero (Pop)
    public static final byte JNZ = 0x32; // Jump if Not Zero (Pop)
    public static final byte EQ = 0x33; // a == b ? 1 : 0
    public static final byte LT = 0x34; // a < b ? 1 : 0
    public static final byte GT = 0x35; // a > b ? 1 : 0

    // Locals
    public static final byte LOAD = 0x40; // Followed by Index (1 byte)
    public static final byte STORE = 0x41; // Followed by Index (1 byte)

    // Method Control
    public static final byte RET = 0x50; // Return top of stack
    public static final byte RET_VOID = 0x51; // Return void

    // Debug
    public static final byte PRINT = 0x7F; // Print Stack Top (Debug)
}
