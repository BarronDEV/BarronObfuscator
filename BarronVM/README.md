# BarronVM - Java Bytecode Virtualization Library

BarronVM is a lightweight, embeddable Virtual Machine for Java. It is designed to interpret a custom instruction set, allowing for high-security obfuscation through virtualization.

## How it Works
Instead of standard JVM Bytecode, methods are compiled into **BarronCode**. These codes are then interpreted at runtime by `BarronVM`. This effectively hides the logic from standard decompilers like JD-GUI, Recaf, and FernFlower.

## Features
- Stack-based Virtual CPU
- Custom Instruction Set Architecture (ISA)
- Lightweight (< 5KB compiled)
- Arithmetic & Logic Support

## Compatibility
- Java 8+
- Standalone (No dependencies)

## Integration
Add this library to your project and call:
```java
BarronVM.exec(bytecode, locals);
```

## License
Private / Proprietary
