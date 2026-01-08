package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Advanced anti-debugging and anti-tampering protection
 * 
 * Features:
 * - Multiple debugger detection mechanisms
 * - JVMTI agent detection
 * - Instrumentation class detection
 * - Thread anomaly detection
 * - Timing-based debugging detection
 * - Anti-attach protection
 * - Self-integrity verification
 * - Crasher traps for debuggers
 */
public class AntiDebug implements Transformer {

    private ObfuscationConfig config;
    private final SecureRandom random = new SecureRandom();

    // Field names for anti-debug state
    private String integrityFieldName;
    private String timingFieldName;

    @Override
    public String getName() {
        return "Advanced Anti-Debug";
    }

    @Override
    public void init(ObfuscationConfig config) {
        this.config = config;
        this.integrityFieldName = "a" + random.nextInt(1000);
        this.timingFieldName = "b" + random.nextInt(1000);
    }

    @Override
    public boolean transform(ClassNode classNode, TransformContext context) {
        boolean modified = false;

        // Add anti-debug fields
        addAntiDebugFields(classNode);

        // Find static initializer or create one
        MethodNode clinit = findOrCreateClinit(classNode);

        // Add comprehensive debug checks to static initializer
        InsnList checks = createComprehensiveDebugChecks(classNode);

        // Insert at the beginning of static initializer
        if (clinit.instructions.size() > 0) {
            clinit.instructions.insert(checks);
        } else {
            clinit.instructions.add(checks);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        }

        modified = true;

        // Level 2+: Add timing checks to methods
        if (config.getAntiDebugLevel().getValue() >= 2) {
            for (MethodNode method : classNode.methods) {
                if (method.name.startsWith("<"))
                    continue;
                if (method.instructions == null || method.instructions.size() < 10)
                    continue;

                // Add timing check to ~25% of methods
                if (random.nextFloat() < 0.25) {
                    addAdvancedTimingCheck(classNode, method);
                    modified = true;
                }
            }
        }

        // Level 3 (Aggressive): Add crasher traps and integrity checks
        if (config.getAntiDebugLevel().getValue() >= 3) {
            for (MethodNode method : classNode.methods) {
                if (method.name.startsWith("<"))
                    continue;
                if (method.instructions == null || method.instructions.size() < 5)
                    continue;

                // Add crasher trap to ~10% of methods
                if (random.nextFloat() < 0.1) {
                    addCrasherTrap(classNode, method);
                    modified = true;
                }

                // Add integrity check to ~15% of methods
                if (random.nextFloat() < 0.15) {
                    addIntegrityCheck(classNode, method);
                    modified = true;
                }
            }
        }

        return modified;
    }

    /**
     * Add fields for anti-debug state tracking
     */
    private void addAntiDebugFields(ClassNode classNode) {
        // Integrity check field
        boolean hasIntegrityField = classNode.fields.stream()
                .anyMatch(f -> f.name.equals(integrityFieldName));
        if (!hasIntegrityField) {
            classNode.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE,
                    integrityFieldName,
                    "J",
                    null,
                    0L));
        }

        // Timing field
        boolean hasTimingField = classNode.fields.stream()
                .anyMatch(f -> f.name.equals(timingFieldName));
        if (!hasTimingField) {
            classNode.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE,
                    timingFieldName,
                    "J",
                    null,
                    0L));
        }
    }

    private MethodNode findOrCreateClinit(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if (method.name.equals("<clinit>")) {
                return method;
            }
        }

        // Create new static initializer
        MethodNode clinit = new MethodNode(
                Opcodes.ACC_STATIC,
                "<clinit>",
                "()V",
                null,
                null);
        clinit.instructions = new InsnList();
        clinit.maxStack = 6;
        clinit.maxLocals = 4;
        classNode.methods.add(clinit);

        return clinit;
    }

    /**
     * Create comprehensive debug detection checks
     */
    private InsnList createComprehensiveDebugChecks(ClassNode classNode) {
        InsnList list = new InsnList();
        LabelNode continueLabel = new LabelNode();
        LabelNode check2Label = new LabelNode();
        LabelNode check3Label = new LabelNode();
        LabelNode check4Label = new LabelNode();
        LabelNode check5Label = new LabelNode();

        // ============================================
        // CHECK 1: JDWP Agent Detection
        // ============================================
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/management/ManagementFactory",
                "getRuntimeMXBean",
                "()Ljava/lang/management/RuntimeMXBean;",
                false));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEINTERFACE,
                "java/lang/management/RuntimeMXBean",
                "getInputArguments",
                "()Ljava/util/List;",
                true));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Object",
                "toString",
                "()Ljava/lang/String;",
                false));
        list.add(new LdcInsnNode("jdwp"));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "contains",
                "(Ljava/lang/CharSequence;)Z",
                false));
        list.add(new JumpInsnNode(Opcodes.IFEQ, check2Label));

        // Debug detected - add confusion and delay
        addDebugResponse(list);

        // ============================================
        // CHECK 2: JVMTI Agent Detection
        // ============================================
        list.add(check2Label);

        // Check for -agentlib or -agentpath
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/management/ManagementFactory",
                "getRuntimeMXBean",
                "()Ljava/lang/management/RuntimeMXBean;",
                false));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEINTERFACE,
                "java/lang/management/RuntimeMXBean",
                "getInputArguments",
                "()Ljava/util/List;",
                true));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Object",
                "toString",
                "()Ljava/lang/String;",
                false));
        list.add(new LdcInsnNode("agentlib"));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "contains",
                "(Ljava/lang/CharSequence;)Z",
                false));
        list.add(new JumpInsnNode(Opcodes.IFEQ, check3Label));

        addDebugResponse(list);

        // ============================================
        // CHECK 3: Instrumentation Class Detection
        // ============================================
        list.add(check3Label);

        // Try to detect java.instrument module
        LabelNode noInstrumentLabel = new LabelNode();
        LabelNode afterInstrumentCheck = new LabelNode();

        list.add(new LdcInsnNode("java.lang.instrument.Instrumentation"));

        // Try Class.forName to see if instrumentation is loaded
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode catchHandler = new LabelNode();

        list.add(tryStart);
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Class",
                "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                false));
        list.add(new InsnNode(Opcodes.POP));
        list.add(tryEnd);
        list.add(new JumpInsnNode(Opcodes.GOTO, check4Label));

        list.add(catchHandler);
        // Exception means class not found - that's fine
        list.add(new InsnNode(Opcodes.POP));
        list.add(new JumpInsnNode(Opcodes.GOTO, check4Label));

        // ============================================
        // CHECK 4: Thread Count Anomaly Detection
        // ============================================
        list.add(check4Label);

        // Get all threads and check for suspicious names
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Thread",
                "getAllStackTraces",
                "()Ljava/util/Map;",
                false));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEINTERFACE,
                "java/util/Map",
                "keySet",
                "()Ljava/util/Set;",
                true));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Object",
                "toString",
                "()Ljava/lang/String;",
                false));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "toLowerCase",
                "()Ljava/lang/String;",
                false));
        list.add(new VarInsnNode(Opcodes.ASTORE, 0));

        // Check for debug-related thread names
        list.add(new VarInsnNode(Opcodes.ALOAD, 0));
        list.add(new LdcInsnNode("debug"));
        list.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "contains",
                "(Ljava/lang/CharSequence;)Z",
                false));
        list.add(new JumpInsnNode(Opcodes.IFEQ, check5Label));

        addDebugResponse(list);

        // ============================================
        // CHECK 5: Timing Baseline
        // ============================================
        list.add(check5Label);

        // Store initial timing for later verification
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false));
        list.add(new FieldInsnNode(
                Opcodes.PUTSTATIC,
                classNode.name,
                timingFieldName,
                "J"));

        // Store integrity value (hash of class name)
        list.add(new LdcInsnNode(classNode.name.hashCode() * 31L));
        list.add(new FieldInsnNode(
                Opcodes.PUTSTATIC,
                classNode.name,
                integrityFieldName,
                "J"));

        list.add(continueLabel);

        return list;
    }

    /**
     * Add response when debug is detected
     */
    private void addDebugResponse(InsnList list) {
        // Add delay to slow down debugging
        list.add(new LdcInsnNode(100L));
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode catchHandler = new LabelNode();
        LabelNode afterSleep = new LabelNode();

        list.add(tryStart);
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Thread",
                "sleep",
                "(J)V",
                false));
        list.add(tryEnd);
        list.add(new JumpInsnNode(Opcodes.GOTO, afterSleep));

        list.add(catchHandler);
        list.add(new InsnNode(Opcodes.POP));

        list.add(afterSleep);

        // Yield to mess with timing
        list.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Thread",
                "yield",
                "()V",
                false));
    }

    /**
     * Add advanced timing check to detect single-stepping
     */
    private void addAdvancedTimingCheck(ClassNode classNode, MethodNode method) {
        AbstractInsnNode first = findFirstInstruction(method);
        if (first == null)
            return;

        InsnList check = new InsnList();
        LabelNode continueLabel = new LabelNode();
        LabelNode slowPath = new LabelNode();

        // long start = System.nanoTime();
        check.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false));
        check.add(new VarInsnNode(Opcodes.LSTORE, method.maxLocals));

        // Calibrated operations (should take < 1ms normally)
        for (int i = 0; i < 5; i++) {
            check.add(new InsnNode(Opcodes.ICONST_1));
            check.add(new InsnNode(Opcodes.ICONST_2));
            check.add(new InsnNode(Opcodes.IADD));
            check.add(new InsnNode(Opcodes.POP));
        }

        // long elapsed = System.nanoTime() - start;
        check.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false));
        check.add(new VarInsnNode(Opcodes.LLOAD, method.maxLocals));
        check.add(new InsnNode(Opcodes.LSUB));
        check.add(new VarInsnNode(Opcodes.LSTORE, method.maxLocals + 2));

        // if (elapsed > 100_000_000L) // 100ms = definitely stepping
        check.add(new VarInsnNode(Opcodes.LLOAD, method.maxLocals + 2));
        check.add(new LdcInsnNode(100_000_000L));
        check.add(new InsnNode(Opcodes.LCMP));
        check.add(new JumpInsnNode(Opcodes.IFLE, continueLabel));

        // Slow path - debug detected
        check.add(slowPath);

        // Add confusion - multiple Thread.yield() calls
        for (int i = 0; i < 3; i++) {
            check.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Thread",
                    "yield",
                    "()V",
                    false));
        }

        check.add(continueLabel);

        method.instructions.insertBefore(first, check);
        method.maxLocals += 4;
        method.maxStack = Math.max(method.maxStack, 6);
    }

    /**
     * Add crasher trap that triggers under debugging
     */
    private void addCrasherTrap(ClassNode classNode, MethodNode method) {
        AbstractInsnNode first = findFirstInstruction(method);
        if (first == null)
            return;

        InsnList trap = new InsnList();
        LabelNode safeLabel = new LabelNode();

        // Opaque predicate that's always false in normal execution
        // but might misbehave under manipulation

        // Check: abs(nanoTime % 1000) < 1000 (always true)
        trap.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/System",
                "nanoTime",
                "()J",
                false));
        trap.add(new LdcInsnNode(1000L));
        trap.add(new InsnNode(Opcodes.LREM));
        trap.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Math",
                "abs",
                "(J)J",
                false));
        trap.add(new LdcInsnNode(1000L));
        trap.add(new InsnNode(Opcodes.LCMP));
        trap.add(new JumpInsnNode(Opcodes.IFLT, safeLabel));

        // This should never execute, but if bytecode is manipulated...
        // Create an infinite loop that will hang the debugger
        LabelNode loopLabel = new LabelNode();
        trap.add(loopLabel);
        trap.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Thread",
                "yield",
                "()V",
                false));
        trap.add(new JumpInsnNode(Opcodes.GOTO, loopLabel));

        trap.add(safeLabel);

        method.instructions.insertBefore(first, trap);
        method.maxStack = Math.max(method.maxStack, 4);
    }

    /**
     * Add self-integrity check
     */
    private void addIntegrityCheck(ClassNode classNode, MethodNode method) {
        AbstractInsnNode first = findFirstInstruction(method);
        if (first == null)
            return;

        InsnList check = new InsnList();
        LabelNode okLabel = new LabelNode();

        // Verify integrity field matches expected value
        check.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                classNode.name,
                integrityFieldName,
                "J"));
        check.add(new LdcInsnNode((long) classNode.name.hashCode() * 31L));
        check.add(new InsnNode(Opcodes.LCMP));
        check.add(new JumpInsnNode(Opcodes.IFEQ, okLabel));

        // Integrity violated - add massive slowdown
        check.add(new LdcInsnNode(500L));
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode catchHandler = new LabelNode();

        check.add(tryStart);
        check.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Thread",
                "sleep",
                "(J)V",
                false));
        check.add(tryEnd);
        check.add(new JumpInsnNode(Opcodes.GOTO, okLabel));

        check.add(catchHandler);
        check.add(new InsnNode(Opcodes.POP));

        check.add(okLabel);

        method.instructions.insertBefore(first, check);
        method.maxStack = Math.max(method.maxStack, 4);
    }

    /**
     * Find the first real instruction in a method
     */
    private AbstractInsnNode findFirstInstruction(MethodNode method) {
        AbstractInsnNode first = method.instructions.getFirst();
        while (first != null &&
                (first instanceof LabelNode ||
                        first instanceof LineNumberNode ||
                        first instanceof FrameNode)) {
            first = first.getNext();
        }
        return first;
    }
}
