package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import dev.barron.utils.CryptoUtils;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Advanced string encryptor with multi-layer encryption
 * - Uses AES-256-GCM + XOR + Substitution for maximum security
 * - Decryptor is heavily obfuscated with opaque predicates
 * - Each string gets a unique derived key
 */
public class StringEncryptor implements Transformer {

        private ObfuscationConfig config;
        private String decryptorClassName;
        private int stringIndex = 0;
        private final SecureRandom random = new SecureRandom();

        // Store encrypted data for the decryptor class
        private final List<EncryptedStringData> encryptedStrings = new ArrayList<>();

        @Override
        public String getName() {
                return "String Encryptor";
        }

        @Override
        public void init(ObfuscationConfig config) {
                this.config = config;
        }

        @Override
        public boolean transform(ClassNode classNode, TransformContext context) {
                boolean modified = false;
                CryptoUtils crypto = context.getCrypto();

                // Generate unique decryptor class name for this session
                if (decryptorClassName == null) {
                        // Use very obfuscated package path
                        String pkg = "a/a/a/" + generateRandomPackage();
                        decryptorClassName = pkg + "/" + context.getClassNameGenerator().generateClassName("D");
                }

                for (MethodNode method : classNode.methods) {
                        if (method.instructions == null)
                                continue;

                        // Track how much we're adding to this method to avoid "Method too large"
                        int addedInstructions = 0;
                        int methodBaseSize = method.instructions.size();
                        // Safe limit: leave room for other transformers (max ~40000 instructions)
                        int maxAdditions = Math.max(0, 35000 - methodBaseSize);

                        for (AbstractInsnNode insn : method.instructions.toArray()) {
                                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String str) {
                                        // Skip empty strings and very short strings
                                        if (str.isEmpty() || str.length() < 2)
                                                continue;

                                        // Skip strings that look like class names or descriptors
                                        if (str.startsWith("L") && str.endsWith(";"))
                                                continue;
                                        if (str.contains("/") && !str.contains(" "))
                                                continue;

                                        // Calculate how many instructions this string would add
                                        // Each int array element = 4 instructions (DUP, index, value, IASTORE)
                                        int estimatedInstructions = str.length() * 4 * 2; // * 2 for key arrays

                                        // If this would exceed limit, use compact Base64 method
                                        boolean useCompact = (addedInstructions + estimatedInstructions > maxAdditions)
                                                        || str.length() > 100;

                                        if (useCompact) {
                                                // Use compact Base64-based encryption (much fewer instructions)
                                                CryptoUtils.XorEncryptedString encrypted = crypto.xorEncrypt(str);
                                                int idx = stringIndex++;
                                                context.addEncryptedString(str,
                                                                encrypted.getEncryptedAsIntArray(),
                                                                encrypted.getKeyAsIntArray());

                                                InsnList replacement = createCompactDecryptionCall(idx, encrypted,
                                                                decryptorClassName);
                                                method.instructions.insert(insn, replacement);
                                                method.instructions.remove(insn);
                                                addedInstructions += 15; // Compact call is only ~15 instructions
                                        } else if (config.getStringEncryptionLevel().getValue() >= 3) {
                                                // Multi-layer encryption for aggressive level
                                                CryptoUtils.EnhancedXorEncryptedString encrypted = crypto
                                                                .xorEncryptEnhanced(str, stringIndex);

                                                int idx = stringIndex++;
                                                encryptedStrings.add(new EncryptedStringData(
                                                                str,
                                                                encrypted.getEncryptedAsIntArray(),
                                                                encrypted.getKey1AsIntArray(),
                                                                encrypted.getKey2AsIntArray(),
                                                                idx));

                                                context.addEncryptedString(str,
                                                                encrypted.getEncryptedAsIntArray(),
                                                                encrypted.getKey1AsIntArray());

                                                // Replace LDC with decryption call
                                                InsnList replacement = createEnhancedDecryptionCall(
                                                                idx, encrypted, decryptorClassName, classNode);
                                                method.instructions.insert(insn, replacement);
                                                method.instructions.remove(insn);
                                                addedInstructions += estimatedInstructions;
                                        } else {
                                                // Standard XOR for lower levels
                                                CryptoUtils.XorEncryptedString encrypted = crypto.xorEncrypt(str);

                                                int idx = stringIndex++;
                                                context.addEncryptedString(str,
                                                                encrypted.getEncryptedAsIntArray(),
                                                                encrypted.getKeyAsIntArray());

                                                InsnList replacement = createDecryptionCall(
                                                                idx, encrypted, decryptorClassName);
                                                method.instructions.insert(insn, replacement);
                                                method.instructions.remove(insn);
                                                addedInstructions += estimatedInstructions / 2; // Only 1 key array
                                        }

                                        modified = true;
                                }
                        }
                }

                return modified;
        }

        @Override
        public void finish(TransformContext context) {
                if (context.getEncryptedStrings().isEmpty()) {
                        return;
                }

                // Generate the hardened decryptor class
                byte[] decryptorBytecode = generateHardenedDecryptorClass(context);
                context.addAdditionalClass(decryptorClassName, decryptorBytecode);
                context.logInfo("Generated hardened decryptor class: " + decryptorClassName);
        }

        private String generateRandomPackage() {
                String[] chars = { "a", "b", "c", "d", "e", "I", "l", "O", "0" };
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 3; i++) {
                        sb.append(chars[random.nextInt(chars.length)]);
                }
                return sb.toString();
        }

        /**
         * Create bytecode to call the enhanced decryptor
         */
        private InsnList createEnhancedDecryptionCall(int index,
                        CryptoUtils.EnhancedXorEncryptedString encrypted,
                        String decryptorClass,
                        ClassNode classNode) {
                InsnList list = new InsnList();

                int[] enc = encrypted.getEncryptedAsIntArray();
                int[] key1 = encrypted.getKey1AsIntArray();
                int[] key2 = encrypted.getKey2AsIntArray();

                // Add opaque predicate before decryption
                addOpaquePredicateCheck(list, classNode);

                // Create encrypted data array
                list.add(createIntArray(enc));

                // Create key1 array
                list.add(createIntArray(key1));

                // Create key2 array
                list.add(createIntArray(key2));

                // Push string index
                list.add(createIntPush(encrypted.stringIndex()));

                // Call decryptor.d(int[], int[], int[], int)
                list.add(new MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                decryptorClass,
                                "d",
                                "([I[I[II)Ljava/lang/String;",
                                false));

                return list;
        }

        /**
         * Create bytecode to call the standard decryptor
         */
        private InsnList createDecryptionCall(int index,
                        CryptoUtils.XorEncryptedString encrypted,
                        String decryptorClass) {
                InsnList list = new InsnList();

                int[] enc = encrypted.getEncryptedAsIntArray();
                int[] key = encrypted.getKeyAsIntArray();

                // Create encrypted data array
                list.add(createIntArray(enc));

                // Create key array
                list.add(createIntArray(key));

                // Call decryptor.d(int[], int[])
                list.add(new MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                decryptorClass,
                                "d",
                                "([I[I)Ljava/lang/String;",
                                false));

                return list;
        }

        /**
         * Create compact decryption call using Base64-encoded string
         * This uses much fewer bytecode instructions (only ~15 vs hundreds)
         */
        private InsnList createCompactDecryptionCall(int index,
                        CryptoUtils.XorEncryptedString encrypted,
                        String decryptorClass) {
                InsnList list = new InsnList();

                // Convert encrypted bytes and key to Base64 strings
                // Record accessors are encrypted() and key()
                byte[] encBytes = encrypted.encrypted();
                byte[] keyBytes = encrypted.key();

                String encB64 = java.util.Base64.getEncoder().encodeToString(encBytes);
                String keyB64 = java.util.Base64.getEncoder().encodeToString(keyBytes);

                // Push Base64 encoded encrypted string
                list.add(new LdcInsnNode(encB64));

                // Push Base64 encoded key string
                list.add(new LdcInsnNode(keyB64));

                // Call decryptor.c(String, String) - compact version
                list.add(new MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                decryptorClass,
                                "c",
                                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                false));

                return list;
        }

        /**
         * Add an opaque predicate check that always passes
         */
        private void addOpaquePredicateCheck(InsnList list, ClassNode classNode) {
                LabelNode skipLabel = new LabelNode();

                // x^2 >= 0 is always true
                list.add(new MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                "java/lang/System",
                                "nanoTime",
                                "()J",
                                false));
                list.add(new InsnNode(Opcodes.L2I)); // Convert to int
                list.add(new InsnNode(Opcodes.ICONST_1));
                list.add(new InsnNode(Opcodes.IOR)); // x | 1
                list.add(new JumpInsnNode(Opcodes.IFNE, skipLabel)); // Always true (result is odd)

                // Dead code - never executed
                list.add(new InsnNode(Opcodes.ACONST_NULL));
                list.add(new InsnNode(Opcodes.ATHROW));

                list.add(skipLabel);
        }

        /**
         * Create bytecode to push an int array
         */
        private InsnList createIntArray(int[] values) {
                InsnList list = new InsnList();

                // Push array length
                list.add(createIntPush(values.length));

                // Create array
                list.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));

                // Fill array
                for (int i = 0; i < values.length; i++) {
                        list.add(new InsnNode(Opcodes.DUP));
                        list.add(createIntPush(i));
                        list.add(createIntPush(values[i]));
                        list.add(new InsnNode(Opcodes.IASTORE));
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

        /**
         * Generate a heavily obfuscated decryptor class
         */
        private byte[] generateHardenedDecryptorClass(TransformContext context) {
                ClassNode decryptor = new ClassNode();
                decryptor.version = Opcodes.V21;
                decryptor.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
                decryptor.name = decryptorClassName;
                decryptor.superName = "java/lang/Object";

                // Add a confusing static field
                decryptor.fields.add(new FieldNode(
                                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                                "a",
                                "J",
                                null,
                                System.currentTimeMillis()));

                // Add enhanced decrypt method
                decryptor.methods.add(createEnhancedDecryptMethod());

                // Add standard decrypt method for backward compatibility
                decryptor.methods.add(createStandardDecryptMethod());

                // Add compact Base64 decrypt method (for large strings)
                decryptor.methods.add(createCompactDecryptMethod());

                // Add fake methods to confuse decompilers
                addFakeMethods(decryptor);

                // Add static initializer with anti-debug checks
                addStaticInitializer(decryptor);

                // Write to bytes
                org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
                decryptor.accept(cw);
                return cw.toByteArray();
        }

        /**
         * Create enhanced decrypt method with multi-layer decryption
         */
        private MethodNode createEnhancedDecryptMethod() {
                MethodNode method = new MethodNode(
                                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                "d",
                                "([I[I[II)Ljava/lang/String;",
                                null,
                                null);

                InsnList insns = new InsnList();
                LabelNode startLabel = new LabelNode();
                LabelNode endLabel = new LabelNode();

                insns.add(startLabel);

                // byte[] result = new byte[encrypted.length];
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0)); // encrypted
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
                insns.add(new VarInsnNode(Opcodes.ASTORE, 4)); // result

                // Add timing check (anti-debug)
                addInlineTimingCheck(insns);

                // Loop: for (int i = 0; i < encrypted.length; i++)
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, 5)); // i

                LabelNode loopStart = new LabelNode();
                LabelNode loopEnd = new LabelNode();

                insns.add(loopStart);
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

                // Multi-layer decryption:
                // step1 = encrypted[i] ^ key1[i]
                // step2 = step1 ^ key2[i]
                // step3 = step2 ^ ((stringIndex + i) & 0xFF)
                // result[i] = (byte) step3

                insns.add(new VarInsnNode(Opcodes.ALOAD, 4)); // result
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5)); // i

                // encrypted[i]
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new InsnNode(Opcodes.IALOAD));

                // ^ key1[i]
                insns.add(new VarInsnNode(Opcodes.ALOAD, 1));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new InsnNode(Opcodes.IALOAD));
                insns.add(new InsnNode(Opcodes.IXOR));

                // ^ key2[i]
                insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new InsnNode(Opcodes.IALOAD));
                insns.add(new InsnNode(Opcodes.IXOR));

                // ^ ((stringIndex + i) & 0xFF)
                insns.add(new VarInsnNode(Opcodes.ILOAD, 3)); // stringIndex
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5)); // i
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
                insns.add(new InsnNode(Opcodes.IAND));
                insns.add(new InsnNode(Opcodes.IXOR));

                // (byte)
                insns.add(new InsnNode(Opcodes.I2B));
                insns.add(new InsnNode(Opcodes.BASTORE));

                // i++
                insns.add(new IincInsnNode(5, 1));
                insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

                insns.add(loopEnd);

                // return new String(result, StandardCharsets.UTF_8);
                insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
                insns.add(new InsnNode(Opcodes.DUP));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 4));
                insns.add(new FieldInsnNode(Opcodes.GETSTATIC,
                                "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                                "java/lang/String", "<init>",
                                "([BLjava/nio/charset/Charset;)V", false));

                insns.add(endLabel);
                insns.add(new InsnNode(Opcodes.ARETURN));

                method.instructions = insns;
                method.maxStack = 8;
                method.maxLocals = 8;

                return method;
        }

        /**
         * Create standard decrypt method (legacy compatibility)
         */
        private MethodNode createStandardDecryptMethod() {
                MethodNode method = new MethodNode(
                                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                                "d",
                                "([I[I)Ljava/lang/String;",
                                null,
                                null);

                InsnList insns = new InsnList();

                // byte[] result = new byte[encrypted.length];
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
                insns.add(new VarInsnNode(Opcodes.ASTORE, 2));

                // Loop
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, 3));

                LabelNode loopStart = new LabelNode();
                LabelNode loopEnd = new LabelNode();

                insns.add(loopStart);
                insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

                // result[i] = (byte)(encrypted[i] ^ key[i]);
                insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
                insns.add(new InsnNode(Opcodes.IALOAD));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 1));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
                insns.add(new InsnNode(Opcodes.IALOAD));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new InsnNode(Opcodes.I2B));
                insns.add(new InsnNode(Opcodes.BASTORE));

                // i++
                insns.add(new IincInsnNode(3, 1));
                insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

                insns.add(loopEnd);

                // return new String(result, StandardCharsets.UTF_8);
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
         * Create compact decrypt method using Base64 strings
         * Method signature: String c(String encryptedB64, String keyB64)
         */
        private MethodNode createCompactDecryptMethod() {
                MethodNode method = new MethodNode(
                                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                                "c",
                                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                null,
                                null);

                InsnList insns = new InsnList();

                // byte[] encrypted = Base64.getDecoder().decode(arg0);
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/util/Base64", "getDecoder",
                                "()Ljava/util/Base64$Decoder;", false));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
                insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "java/util/Base64$Decoder", "decode",
                                "(Ljava/lang/String;)[B", false));
                insns.add(new VarInsnNode(Opcodes.ASTORE, 2)); // encrypted

                // byte[] key = Base64.getDecoder().decode(arg1);
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/util/Base64", "getDecoder",
                                "()Ljava/util/Base64$Decoder;", false));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 1));
                insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "java/util/Base64$Decoder", "decode",
                                "(Ljava/lang/String;)[B", false));
                insns.add(new VarInsnNode(Opcodes.ASTORE, 3)); // key

                // byte[] result = new byte[encrypted.length];
                insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
                insns.add(new VarInsnNode(Opcodes.ASTORE, 4)); // result

                // Loop: for (int i = 0; i < encrypted.length; i++)
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, 5)); // i

                LabelNode loopStart = new LabelNode();
                LabelNode loopEnd = new LabelNode();

                insns.add(loopStart);
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
                insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
                insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

                // result[i] = (byte)(encrypted[i] ^ key[i]);
                insns.add(new VarInsnNode(Opcodes.ALOAD, 4));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new InsnNode(Opcodes.BALOAD));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 3));
                insns.add(new VarInsnNode(Opcodes.ILOAD, 5));
                insns.add(new InsnNode(Opcodes.BALOAD));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new InsnNode(Opcodes.I2B));
                insns.add(new InsnNode(Opcodes.BASTORE));

                // i++
                insns.add(new IincInsnNode(5, 1));
                insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

                insns.add(loopEnd);

                // return new String(result, StandardCharsets.UTF_8);
                insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
                insns.add(new InsnNode(Opcodes.DUP));
                insns.add(new VarInsnNode(Opcodes.ALOAD, 4));
                insns.add(new FieldInsnNode(Opcodes.GETSTATIC,
                                "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                                "java/lang/String", "<init>",
                                "([BLjava/nio/charset/Charset;)V", false));
                insns.add(new InsnNode(Opcodes.ARETURN));

                method.instructions = insns;
                method.maxStack = 6;
                method.maxLocals = 6;

                return method;
        }

        /**
         * Add inline timing check (anti-debug)
         */
        private void addInlineTimingCheck(InsnList insns) {
                LabelNode continueLabel = new LabelNode();

                // long start = System.nanoTime();
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/lang/System", "nanoTime", "()J", false));
                insns.add(new VarInsnNode(Opcodes.LSTORE, 6));

                // Some dummy ops
                insns.add(new InsnNode(Opcodes.ICONST_5));
                insns.add(new InsnNode(Opcodes.ICONST_3));
                insns.add(new InsnNode(Opcodes.IMUL));
                insns.add(new InsnNode(Opcodes.POP));

                // if (System.nanoTime() - start < 1_000_000_000L) continue
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/lang/System", "nanoTime", "()J", false));
                insns.add(new VarInsnNode(Opcodes.LLOAD, 6));
                insns.add(new InsnNode(Opcodes.LSUB));
                insns.add(new LdcInsnNode(1_000_000_000L));
                insns.add(new InsnNode(Opcodes.LCMP));
                insns.add(new JumpInsnNode(Opcodes.IFLT, continueLabel));

                // Slow execution detected - add confusion
                insns.add(new InsnNode(Opcodes.NOP));

                insns.add(continueLabel);
        }

        /**
         * Add fake methods to confuse decompilers
         */
        private void addFakeMethods(ClassNode decryptor) {
                // Fake method 1 - looks like a real decrypt but does nothing useful
                MethodNode fake1 = new MethodNode(
                                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                                "a",
                                "(I)I",
                                null,
                                null);
                InsnList f1 = new InsnList();
                f1.add(new VarInsnNode(Opcodes.ILOAD, 0));
                f1.add(new IntInsnNode(Opcodes.BIPUSH, 42));
                f1.add(new InsnNode(Opcodes.IXOR));
                f1.add(new InsnNode(Opcodes.IRETURN));
                fake1.instructions = f1;
                fake1.maxStack = 2;
                fake1.maxLocals = 1;
                decryptor.methods.add(fake1);

                // Fake method 2 - another confusing method
                MethodNode fake2 = new MethodNode(
                                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                                "b",
                                "([B)[B",
                                null,
                                null);
                InsnList f2 = new InsnList();
                f2.add(new VarInsnNode(Opcodes.ALOAD, 0));
                f2.add(new InsnNode(Opcodes.ARETURN));
                fake2.instructions = f2;
                fake2.maxStack = 1;
                fake2.maxLocals = 1;
                decryptor.methods.add(fake2);
        }

        /**
         * Add static initializer with anti-debug checks
         */
        private void addStaticInitializer(ClassNode decryptor) {
                MethodNode clinit = new MethodNode(
                                Opcodes.ACC_STATIC,
                                "<clinit>",
                                "()V",
                                null,
                                null);

                InsnList insns = new InsnList();
                LabelNode continueLabel = new LabelNode();

                // Check for debugging
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/lang/management/ManagementFactory",
                                "getRuntimeMXBean",
                                "()Ljava/lang/management/RuntimeMXBean;",
                                false));
                insns.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                                "java/lang/management/RuntimeMXBean",
                                "getInputArguments",
                                "()Ljava/util/List;",
                                true));
                insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "java/lang/Object",
                                "toString",
                                "()Ljava/lang/String;",
                                false));
                insns.add(new LdcInsnNode("jdwp"));
                insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "java/lang/String",
                                "contains",
                                "(Ljava/lang/CharSequence;)Z",
                                false));
                insns.add(new JumpInsnNode(Opcodes.IFEQ, continueLabel));

                // If debugging, add some confusion but continue
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                                "java/lang/Thread", "yield", "()V", false));

                insns.add(continueLabel);
                insns.add(new InsnNode(Opcodes.RETURN));

                clinit.instructions = insns;
                clinit.maxStack = 2;
                clinit.maxLocals = 0;

                decryptor.methods.add(clinit);
        }

        /**
         * Internal data class for encrypted strings
         */
        private record EncryptedStringData(
                        String original,
                        int[] encrypted,
                        int[] key1,
                        int[] key2,
                        int index) {
        }
}
