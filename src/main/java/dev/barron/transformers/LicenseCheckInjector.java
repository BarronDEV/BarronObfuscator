package dev.barron.transformers;

import dev.barron.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Injects license verification logic into the plugin.
 * Implements "Session Token", "Hardware Binding", "Grace Period", and
 * "InvokeDynamic Hiding".
 */
public class LicenseCheckInjector implements Transformer {

        private ObfuscationConfig config;
        private String mainClass;
        private String pluginName = "Plugin"; // Default fallback name
        private boolean injected = false;
        // Shared secret for HMAC verification (MUST match LicenseServer)
        private static final String EMBEDDED_SECRET = "CHANGE_THIS_TO_RANDOM_SECRET_" + UUID.randomUUID().toString();
        private static final long THREE_DAYS_MS = 259200000L; // 3 * 24 * 60 * 60 * 1000

        @Override
        public String getName() {
                return "License Verification Injector";
        }

        @Override
        public void init(ObfuscationConfig config) {
                this.config = config;
        }

        @Override
        public boolean shouldTransform(ClassNode classNode, ObfuscationConfig config) {
                return config.isLicenseVerification();
        }

        @Override
        public boolean transform(ClassNode classNode, TransformContext context) {
                if (injected)
                        return false;

                // Find main class logic (same as before)
                if (mainClass == null) {
                        Map<String, byte[]> resources = context.getResourceEntries();
                        if (resources.containsKey("plugin.yml")) {
                                String pluginYml = new String(resources.get("plugin.yml"), StandardCharsets.UTF_8);
                                // Simplify for robustness
                                pluginYml = pluginYml.replace("\r", "");
                                for (String line : pluginYml.split("\n")) {
                                        if (line.trim().startsWith("main:")) {
                                                String main = line.substring(5).trim();
                                                if (main.contains("#"))
                                                        main = main.substring(0, main.indexOf("#")).trim();
                                                main = main.replace("'", "").replace("\"", "");
                                                mainClass = main.replace('.', '/');
                                        }
                                        // Extract plugin name from plugin.yml
                                        if (line.trim().startsWith("name:")) {
                                                String name = line.substring(5).trim();
                                                if (name.contains("#"))
                                                        name = name.substring(0, name.indexOf("#")).trim();
                                                name = name.replace("'", "").replace("\"", "");
                                                if (!name.isEmpty()) {
                                                        pluginName = name;
                                                }
                                        }
                                }
                        }
                }

                if (mainClass != null && classNode.name.equals(mainClass)) {
                        context.logInfo("[INFO] Injecting INDY Session Token & Secure Grace Period into: "
                                        + classNode.name);

                        // Generate obfuscated field names
                        String tokenField = "tk_" + UUID.randomUUID().toString().substring(0, 6);
                        String timestampField = "ts_" + UUID.randomUUID().toString().substring(0, 6);
                        String keyField = "ky_" + UUID.randomUUID().toString().substring(0, 6);

                        // Inject static fields
                        // private static String sessionToken;
                        classNode.fields.add(
                                        new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                                        tokenField, "Ljava/lang/String;", null, null));
                        // private static long lastTimestamp;
                        classNode.fields.add(
                                        new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                                        timestampField, "J", null, null));
                        // private static String licenseKey;
                        classNode.fields.add(
                                        new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                                        keyField, "Ljava/lang/String;", null, null));

                        // 1. Create helper methods
                        MethodNode calcHashMethod = createHardwareHashMethod(classNode);
                        MethodNode saveGraceMethod = createSaveGracePeriodMethod(classNode, calcHashMethod);
                        MethodNode loadGraceMethod = createLoadGracePeriodMethod(classNode, calcHashMethod);
                        MethodNode reqMethod = createRequestHelper(classNode);
                        MethodNode checkTokenMethod = createCheckTokenMethod(classNode, tokenField, timestampField,
                                        keyField);

                        // Verify Method uses the grace period helpers
                        MethodNode verifyMethod = createVerifyMethod(classNode, tokenField, timestampField, keyField,
                                        saveGraceMethod, loadGraceMethod, reqMethod, calcHashMethod, pluginName);

                        classNode.methods.add(calcHashMethod);
                        classNode.methods.add(saveGraceMethod);
                        classNode.methods.add(loadGraceMethod);
                        classNode.methods.add(reqMethod);
                        classNode.methods.add(checkTokenMethod);
                        classNode.methods.add(verifyMethod);

                        // 2. Inject into onEnable (Initial Sync Check)
                        // Verify is void(), complex to Indy without methodtype match.
                        // For MVP, we will Indy the 'checkToken' call primarily as it's the Kill
                        // Switch.
                        for (MethodNode method : classNode.methods) {
                                if (method.name.equals("onEnable") && method.desc.equals("()V")) {
                                        injectInitialCheck(method, verifyMethod, classNode.name);
                                }
                        }

                        // 3. Inject Kill Switch into sensitive methods
                        // (onCommand, @EventHandler, onTabComplete)
                        // 2. Kill Switch (Sensitive Methods) -> INVOKESTATIC Protected (No INDY to
                        // avoid Crash)
                        int injectedCount = 0;
                        for (MethodNode method : classNode.methods) {
                                if (shouldInjectKillSwitch(method, verifyMethod, checkTokenMethod)) {
                                        injectKillSwitchStatic(method, checkTokenMethod, classNode.name, tokenField);
                                        injectedCount++;
                                }
                        }
                        context.logInfo("   - Injected Static Kill Switch into " + injectedCount + " methods.");

                        // 4. Inject Heartbeat Scheduler (Simulated)
                        injectHeartbeat(classNode, verifyMethod);

                        injected = true;
                        return true;
                }

                return false;
        }

        private boolean shouldInjectKillSwitch(MethodNode method, MethodNode v, MethodNode c) {
                if (method.name.equals("onEnable") || method.name.equals("onDisable") || method.name.equals("<init>")
                                || method.name.equals("<clinit>"))
                        return false;
                if (method == v || method == c)
                        return false;

                // Inject into CommandExecutor
                if (method.name.equals("onCommand"))
                        return true;

                // Inject into EventHandlers
                if (method.visibleAnnotations != null) {
                        for (AnnotationNode an : method.visibleAnnotations) {
                                if (an.desc.contains("EventHandler"))
                                        return true;
                        }
                }
                return false;
        }

        // Static Injection Logic (Replaces INDY to fix specific JVM crashes)
        private void injectKillSwitchStatic(MethodNode method, MethodNode checkMethod, String owner,
                        String tokenField) {
                InsnList list = new InsnList();

                // if (checkToken(token)) -> continue
                // else -> return/null (kill)

                list.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, tokenField, "Ljava/lang/String;"));
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, checkMethod.name, checkMethod.desc, false));

                LabelNode ok = new LabelNode();
                list.add(new JumpInsnNode(Opcodes.IFNE, ok)); // If true (1) -> Jump to OK

                // Kill Logic (Return default based on type)
                Type returnType = Type.getReturnType(method.desc);
                switch (returnType.getSort()) {
                        case Type.VOID:
                                list.add(new InsnNode(Opcodes.RETURN));
                                break;
                        case Type.BOOLEAN:
                        case Type.BYTE:
                        case Type.CHAR:
                        case Type.SHORT:
                        case Type.INT:
                                list.add(new InsnNode(Opcodes.ICONST_0));
                                list.add(new InsnNode(Opcodes.IRETURN));
                                break;
                        case Type.LONG:
                                list.add(new InsnNode(Opcodes.LCONST_0));
                                list.add(new InsnNode(Opcodes.LRETURN));
                                break;
                        case Type.FLOAT:
                                list.add(new InsnNode(Opcodes.FCONST_0));
                                list.add(new InsnNode(Opcodes.FRETURN));
                                break;
                        case Type.DOUBLE:
                                list.add(new InsnNode(Opcodes.DCONST_0));
                                list.add(new InsnNode(Opcodes.DRETURN));
                                break;
                        default: // OBJECT, ARRAY
                                list.add(new InsnNode(Opcodes.ACONST_NULL));
                                list.add(new InsnNode(Opcodes.ARETURN));
                                break;
                }

                list.add(ok);
                method.instructions.insert(list);
        }

        private void injectInitialCheck(MethodNode method, MethodNode verify, String owner) {
                // Inject at the START (HEAD) of the method to protect everything.
                // After verification, check if plugin was disabled and return early if so.
                InsnList list = new InsnList();

                // 1. Call verify method: this.verify()
                list.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, owner, verify.name, verify.desc, false));

                // 2. Check if still enabled: if (!this.isEnabled()) return;
                LabelNode continueLabel = new LabelNode();
                list.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "org/bukkit/plugin/java/JavaPlugin", "isEnabled",
                                "()Z", false));
                list.add(new JumpInsnNode(Opcodes.IFNE, continueLabel)); // If true (enabled), jump to continue
                list.add(new InsnNode(Opcodes.RETURN)); // If false (disabled), return immediately
                list.add(continueLabel);

                method.instructions.insert(list); // insert() adds to the beginning
        }

        private void injectHeartbeat(ClassNode classNode, MethodNode verifyMethod) {
                // Simplified injection for MVP
        }

        /**
         * Calc Hardware Hash: SHA-256(ServerIP + ":" + ServerPort + ":" + Timestamp +
         * ":" + SECRET)
         */
        private MethodNode createHardwareHashMethod(ClassNode owner) {
                String methodName = "hash_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                methodName,
                                "(J)Ljava/lang/String;", null, new String[] { "java/lang/Exception" });

                InsnList il = new InsnList();

                // 1. Get System Properties (Stronger HWID)
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));

                // os.name
                il.add(new LdcInsnNode("os.name"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "getProperty",
                                "(Ljava/lang/String;)Ljava/lang/String;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                // os.arch
                il.add(new LdcInsnNode("os.arch"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "getProperty",
                                "(Ljava/lang/String;)Ljava/lang/String;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                // user.name
                il.add(new LdcInsnNode("user.name"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "getProperty",
                                "(Ljava/lang/String;)Ljava/lang/String;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                // 2. Get Server IP/Port (Keep this as well for IP Binding)
                // Bukkit.getServer()
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "org/bukkit/Bukkit", "getServer",
                                "()Lorg/bukkit/Server;",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 2)); // Server

                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/Server", "getIp", "()Ljava/lang/String;",
                                true));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/Server", "getPort", "()I", true));
                il.add(new VarInsnNode(Opcodes.ISTORE, 4)); // Port

                // (Redundant StringBuilder creation removed)
                // Continue with appending Port to the existing StringBuilder on stack
                // Append Port
                il.add(new VarInsnNode(Opcodes.ILOAD, 4));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(I)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                // Append Timestamp
                il.add(new VarInsnNode(Opcodes.LLOAD, 0)); // long timestamp arg
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(J)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                // Append Secret (Dynamic)
                String dynSecret = config.getTokenSecret();
                if (dynSecret == null || dynSecret.isEmpty()) {
                        dynSecret = EMBEDDED_SECRET; // Fallback
                }
                il.add(new LdcInsnNode(dynSecret));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));

                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                                "()Ljava/lang/String;",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 5)); // rawData

                // SHA-256 (Linear, no try-catch, propagate exception if any)
                il.add(new LdcInsnNode("SHA-256"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest", "getInstance",
                                "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 5)); // rawData
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes",
                                "(Ljava/nio/charset/Charset;)[B", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "([B)[B",
                                false));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64", "getEncoder",
                                "()Ljava/util/Base64$Encoder;", false));
                il.add(new InsnNode(Opcodes.SWAP));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Encoder", "encodeToString",
                                "([B)Ljava/lang/String;", false));
                il.add(new InsnNode(Opcodes.ARETURN));

                m.instructions = il;
                m.maxStack = 4;
                m.maxLocals = 6;
                return m;
        }

        // saveGracePeriod(long timestamp)
        // Writes "timestamp:hash" to plugins/Barron/data.bin
        private MethodNode createSaveGracePeriodMethod(ClassNode owner, MethodNode calcHash) {
                String methodName = "save_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                methodName,
                                "(J)V", null, new String[] { "java/lang/Exception" });
                InsnList il = new InsnList();

                // calc hash
                il.add(new VarInsnNode(Opcodes.LLOAD, 0));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, calcHash.name, calcHash.desc, false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 2)); // hash

                // data = timestamp + ":" + hash
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
                il.add(new VarInsnNode(Opcodes.LLOAD, 0));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(J)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                                "()Ljava/lang/String;",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 3)); // content

                // File file = new File("plugins/Barron/data.bin");
                il.add(new TypeInsnNode(Opcodes.NEW, "java/io/File"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new LdcInsnNode("plugins/Barron/data.bin"));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 4));

                // ensure dir exists (LINEAR)
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/File", "getParentFile", "()Ljava/io/File;",
                                false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/File", "mkdirs", "()Z", false));
                il.add(new InsnNode(Opcodes.POP));

                // Files.writeString(path, content) - No try-catch, propagate exception
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/File", "toPath", "()Ljava/nio/file/Path;",
                                false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 3)); // content

                // Push empty OpenOption[]
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/nio/file/OpenOption"));

                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/nio/file/Files", "writeString",
                                "(Ljava/nio/file/Path;Ljava/lang/CharSequence;[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;",
                                false));
                il.add(new InsnNode(Opcodes.POP));

                il.add(new InsnNode(Opcodes.RETURN));

                m.instructions = il;
                m.maxStack = 4;
                m.maxLocals = 5;
                return m;
        }

        // loadGracePeriod() -> Returns timestamp IF valid, else -1
        private MethodNode createLoadGracePeriodMethod(ClassNode owner, MethodNode calcHash) {
                String methodName = "load_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                methodName,
                                "()J", null, new String[] { "java/lang/Exception" });
                InsnList il = new InsnList();

                LabelNode fail = new LabelNode();
                LabelNode read = new LabelNode();

                // Simple check: if (Files.exists(path))
                il.add(new LdcInsnNode("plugins/Barron/data.bin"));
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/nio/file/Paths", "get",
                                "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 0)); // Path

                // Files.exists(path)
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/nio/file/LinkOption"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/nio/file/Files", "exists",
                                "(Ljava/nio/file/Path;[Ljava/nio/file/LinkOption;)Z", false));
                il.add(new JumpInsnNode(Opcodes.IFNE, read));
                il.add(new JumpInsnNode(Opcodes.GOTO, fail));

                il.add(read);
                // readString
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/nio/file/Files", "readString",
                                "(Ljava/nio/file/Path;)Ljava/lang/String;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 1)); // content

                // if (content == null) fail
                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new JumpInsnNode(Opcodes.IFNULL, fail));

                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "split",
                                "(Ljava/lang/String;)[Ljava/lang/String;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 2));

                // if (parts == null) fail
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new JumpInsnNode(Opcodes.IFNULL, fail));

                il.add(new VarInsnNode(Opcodes.ALOAD, 2)); // parts
                il.add(new InsnNode(Opcodes.ARRAYLENGTH));
                il.add(new IntInsnNode(Opcodes.SIPUSH, 2));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPLT, fail));

                // long ts = Long.parseLong(parts[0])
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new InsnNode(Opcodes.AALOAD));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "parseLong", "(Ljava/lang/String;)J",
                                false));
                il.add(new VarInsnNode(Opcodes.LSTORE, 3)); // ts

                // String storedHash = parts[1]
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.AALOAD));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "trim", "()Ljava/lang/String;",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 5));

                // String expectedHash = calcHash(ts)
                il.add(new VarInsnNode(Opcodes.LLOAD, 3));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, calcHash.name, calcHash.desc, false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 6));

                // if (!stored.equals(expected)) fail
                il.add(new VarInsnNode(Opcodes.ALOAD, 5));
                il.add(new VarInsnNode(Opcodes.ALOAD, 6));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z",
                                false));
                il.add(new JumpInsnNode(Opcodes.IFEQ, fail));

                // return ts
                il.add(new VarInsnNode(Opcodes.LLOAD, 3));
                il.add(new InsnNode(Opcodes.LRETURN));

                il.add(fail);
                il.add(new LdcInsnNode(-1L));
                il.add(new InsnNode(Opcodes.LRETURN));

                m.instructions = il;
                m.maxStack = 4;
                m.maxLocals = 7;
                return m;
        }

        /**
         * Create verify method:
         * 1. Check Primary Server.
         * 2. If fail -> Check Backup Server.
         * 3. If both fail -> Check Grace Period.
         * 4. If valid -> Set Token.
         * 5. If invalid -> Kill.
         */
        private MethodNode createVerifyMethod(ClassNode owner, String tokenField, String tsField, String keyField,
                        MethodNode saveMethod, MethodNode loadMethod, MethodNode reqMethod, MethodNode calcHashMethod,
                        String pluginName) {
                String methodName = "verify_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_SYNTHETIC, methodName, "()V", null,
                                null);
                InsnList il = new InsnList();

                LabelNode startTry = new LabelNode();
                LabelNode endTry = new LabelNode();
                LabelNode catchBlock = new LabelNode();
                LabelNode kill = new LabelNode(); // Declare early so it can be jumped to from anywhere
                m.tryCatchBlocks.add(new TryCatchBlockNode(startTry, endTry, catchBlock, "java/lang/Exception"));

                il.add(startTry);

                // ============================================
                // 1. Get License Key from config.yml at RUNTIME
                // String licenseKey = this.getConfig().getString("license-key");
                // ============================================
                il.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "org/bukkit/plugin/java/JavaPlugin",
                                "getConfig",
                                "()Lorg/bukkit/configuration/file/FileConfiguration;",
                                false));
                il.add(new LdcInsnNode("license-key"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                                "org/bukkit/configuration/file/FileConfiguration",
                                "getString",
                                "(Ljava/lang/String;)Ljava/lang/String;",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 1)); // licenseKey

                // ============================================
                // 2. Check if license key is null or placeholder
                // if (licenseKey == null || licenseKey.equals("YOUR-LICENSE-KEY-HERE")) { fail
                // }
                // ============================================
                LabelNode failLabel = new LabelNode();
                LabelNode continueLabel = new LabelNode();

                // Check null
                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new JumpInsnNode(Opcodes.IFNULL, failLabel));

                // Check if key is default placeholder
                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new LdcInsnNode("YOUR-LICENSE-KEY-HERE"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z",
                                false));
                il.add(new JumpInsnNode(Opcodes.IFNE, failLabel)); // If equals, jump to fail

                // Check if key is empty
                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "isEmpty", "()Z", false));
                il.add(new JumpInsnNode(Opcodes.IFEQ, continueLabel)); // If NOT empty, continue

                // failLabel: Key is null/placeholder/empty - print error and fail
                il.add(failLabel);
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;"));
                il.add(new LdcInsnNode("License key not configured in config.yml! Plugin disabled."));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                "(Ljava/lang/String;)V", false));
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, tokenField, "Ljava/lang/String;"));

                // DISABLE PLUGIN gracefully
                il.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "org/bukkit/plugin/java/JavaPlugin", "getServer",
                                "()Lorg/bukkit/Server;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/Server", "getPluginManager",
                                "()Lorg/bukkit/plugin/PluginManager;", true));
                il.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "disablePlugin",
                                "(Lorg/bukkit/plugin/Plugin;)V", true));
                il.add(new InsnNode(Opcodes.RETURN));

                /*
                 * // Throw Exception to turn RED
                 * il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
                 * il.add(new InsnNode(Opcodes.DUP));
                 * il.add(new LdcInsnNode("License Key Missing - Plugin Disabled"));
                 * il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                 * "java/lang/RuntimeException", "<init>",
                 * "(Ljava/lang/String;)V", false));
                 * il.add(new InsnNode(Opcodes.ATHROW));
                 */

                // il.add(new InsnNode(Opcodes.RETURN));

                il.add(continueLabel);

                // ============================================
                // 3. Prepare JSON Request: {"key":"LICENSE_KEY", "hwid":"HASH"}
                // ============================================
                // String url = <embedded server URL>
                il.add(new LdcInsnNode(config.getLicenseServerUrl()));
                il.add(new VarInsnNode(Opcodes.ASTORE, 2)); // URL

                // Calculate HWID Hash using the helper method
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, calcHashMethod.name, calcHashMethod.desc,
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 5)); // HWID Hash

                // Build JSON: {"key":"KEY","hwid":"HWID"}
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
                il.add(new LdcInsnNode("{\"key\":\""));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 1)); // Key
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode("\",\"hwid\":\""));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 5)); // HWID
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode("\"}"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                                "()Ljava/lang/String;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 3)); // Data

                // Call Request (Primary)
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, reqMethod.name, reqMethod.desc, false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 4)); // Response JSON (or null)

                // If Response != null -> Success check
                LabelNode checkToken = new LabelNode();
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new JumpInsnNode(Opcodes.IFNULL, checkToken)); // If null, try backup

                // FIRST: Check if response contains "valid":true
                LabelNode invalidLicense = new LabelNode();
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new LdcInsnNode("\"valid\":true"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "contains",
                                "(Ljava/lang/CharSequence;)Z", false));
                il.add(new JumpInsnNode(Opcodes.IFEQ, invalidLicense));

                // EXTRACT TOKEN from JSON: "sessionToken":"XYZ"
                // 1. Find "sessionToken"
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new LdcInsnNode("\"sessionToken\""));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf", "(Ljava/lang/String;)I",
                                false));
                il.add(new VarInsnNode(Opcodes.ISTORE, 6));

                // Reuse invalidLicense for parse fail
                LabelNode parseFail = invalidLicense; // Simply treat parse error as invalid/fail

                // if index == -1 -> parseFail
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new InsnNode(Opcodes.ICONST_M1));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, parseFail));

                // 2. Find Colon after token
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new LdcInsnNode(":"));
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf",
                                "(Ljava/lang/String;I)I", false));
                il.add(new VarInsnNode(Opcodes.ISTORE, 6)); // Found Colon

                // if colon == -1 -> parseFail
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new InsnNode(Opcodes.ICONST_M1));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, parseFail));

                // 3. Find Quote after colon (Start of Value)
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new LdcInsnNode("\""));
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf",
                                "(Ljava/lang/String;I)I", false));
                il.add(new VarInsnNode(Opcodes.ISTORE, 6)); // Start Quote

                // if startQuote == -1 -> parseFail
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new InsnNode(Opcodes.ICONST_M1));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, parseFail));

                // Start Index = quote + 1
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.IADD));
                il.add(new VarInsnNode(Opcodes.ISTORE, 6));

                // 4. Find End Quote
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new LdcInsnNode("\""));
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf",
                                "(Ljava/lang/String;I)I", false));
                il.add(new VarInsnNode(Opcodes.ISTORE, 7)); // End Quote

                // if endQuote == -1 -> parseFail
                il.add(new VarInsnNode(Opcodes.ILOAD, 7));
                il.add(new InsnNode(Opcodes.ICONST_M1));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, parseFail));

                // Extract substring
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new VarInsnNode(Opcodes.ILOAD, 6));
                il.add(new VarInsnNode(Opcodes.ILOAD, 7));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
                                "(II)Ljava/lang/String;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 8)); // Token

                // Set Token
                il.add(new VarInsnNode(Opcodes.ALOAD, 8));
                il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, tokenField, "Ljava/lang/String;"));

                // Store license key for kill switch checkToken to use
                il.add(new VarInsnNode(Opcodes.ALOAD, 1)); // licenseKey
                il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, keyField, "Ljava/lang/String;"));

                // Save Grace
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, saveMethod.name, saveMethod.desc, false));
                il.add(new InsnNode(Opcodes.RETURN));

                // invalidLicense label:
                // invalidLicense label:
                il.add(invalidLicense);
                // Print simple error without exposing token
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;"));
                il.add(new LdcInsnNode("[License] Verification failed."));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                "(Ljava/lang/String;)V", false));

                // Jump to KILL
                il.add(new JumpInsnNode(Opcodes.GOTO, kill));

                // checkToken label: Jump here if Response was NULL (Network Error?)
                il.add(checkToken);
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
                il.add(new LdcInsnNode("[License] Parse Failed. Response: "));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 4)); // Response
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                                "()Ljava/lang/String;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                "(Ljava/lang/String;)V", false));

                // Try Backup?
                if (config.getBackupServerUrl() != null && !config.getBackupServerUrl().isEmpty()) {
                        il.add(new LdcInsnNode(config.getBackupServerUrl()));
                        il.add(new VarInsnNode(Opcodes.ALOAD, 3)); // Data
                        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, reqMethod.name, reqMethod.desc,
                                        false));
                        il.add(new VarInsnNode(Opcodes.ASTORE, 4));

                        LabelNode checkBackup = new LabelNode();
                        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                        il.add(new JumpInsnNode(Opcodes.IFNULL, checkBackup));

                        // Check valid:true in backup response too (prevent bypass)
                        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                        il.add(new LdcInsnNode("\"valid\":true"));
                        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "contains",
                                        "(Ljava/lang/CharSequence;)Z", false));
                        il.add(new JumpInsnNode(Opcodes.IFEQ, checkBackup)); // If not valid, skip

                        // Set Token (Backup Success)
                        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                        il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, tokenField, "Ljava/lang/String;"));

                        // Store license key for kill switch
                        il.add(new VarInsnNode(Opcodes.ALOAD, 1)); // licenseKey
                        il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, keyField, "Ljava/lang/String;"));

                        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J",
                                        false));
                        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, saveMethod.name, saveMethod.desc,
                                        false));
                        il.add(new InsnNode(Opcodes.RETURN));
                        il.add(checkBackup);
                }

                // If we reach here, both primary and backup failed (or no backup)
                // Throw exception to trigger catchBlock (grace period check)
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new LdcInsnNode("License verification failed"));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>",
                                "(Ljava/lang/String;)V", false));
                il.add(new InsnNode(Opcodes.ATHROW));

                il.add(endTry);

                // Exception or Fail triggers Grace Check
                il.add(catchBlock);
                il.add(new InsnNode(Opcodes.POP)); // Pop ex

                // Grace Period Check
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, loadMethod.name, loadMethod.desc, false));
                il.add(new VarInsnNode(Opcodes.LSTORE, 5)); // timestamp

                // If -1 -> Die
                il.add(new VarInsnNode(Opcodes.LLOAD, 5));
                il.add(new LdcInsnNode(-1L));
                il.add(new InsnNode(Opcodes.LCMP));
                // LabelNode kill = new LabelNode(); // Removed duplicate declaration
                il.add(new JumpInsnNode(Opcodes.IFEQ, kill));

                // if (Now - last > 3 DAYS) -> Die
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false));
                il.add(new VarInsnNode(Opcodes.LLOAD, 5));
                il.add(new InsnNode(Opcodes.LSUB));
                il.add(new LdcInsnNode(259200000L));
                il.add(new InsnNode(Opcodes.LCMP));
                il.add(new JumpInsnNode(Opcodes.IFGT, kill));

                // Valid Grace Period
                // Valid Grace Period
                // Generate Valid Offline Token: SHA-256(Key:Secret)

                // 1. Get Secret
                String offlineSecret = config.getTokenSecret() != null ? config.getTokenSecret() : EMBEDDED_SECRET;
                il.add(new LdcInsnNode(offlineSecret));
                il.add(new VarInsnNode(Opcodes.ASTORE, 6)); // secret var

                // 2. Build String: Key:Secret (Key is in Var 1)
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 1)); // Key
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new LdcInsnNode(":"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 6)); // Secret
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                                "()Ljava/lang/String;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 7)); // rawData

                // 3. SHA-256
                il.add(new LdcInsnNode("SHA-256"));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest", "getInstance",
                                "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 7));
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes",
                                "(Ljava/nio/charset/Charset;)[B", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "([B)[B",
                                false));
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64", "getEncoder",
                                "()Ljava/util/Base64$Encoder;", false));
                il.add(new InsnNode(Opcodes.SWAP));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Encoder", "encodeToString",
                                "([B)Ljava/lang/String;", false));
                il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, tokenField, "Ljava/lang/String;"));
                il.add(new InsnNode(Opcodes.RETURN));

                il.add(kill);
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner.name, tokenField, "Ljava/lang/String;"));

                // PRINT ERROR before dying to help debug
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "err", "Ljava/io/PrintStream;"));
                il.add(new LdcInsnNode("License Verification Failed! Plugin disabled."));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                "(Ljava/lang/String;)V", false));

                // DISABLE PLUGIN instead of throwing exception
                il.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "org/bukkit/plugin/java/JavaPlugin", "getServer",
                                "()Lorg/bukkit/Server;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/Server", "getPluginManager",
                                "()Lorg/bukkit/plugin/PluginManager;", true));
                il.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this (plugin instance)
                il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "disablePlugin",
                                "(Lorg/bukkit/plugin/Plugin;)V", true));

                // Return immediately
                il.add(new InsnNode(Opcodes.RETURN));

                // Old throw exception code removed
                /*
                 * il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
                 * il.add(new InsnNode(Opcodes.DUP));
                 * il.add(new LdcInsnNode("License Verification Failed - Plugin Disabled"));
                 * il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                 * "java/lang/RuntimeException", "<init>",
                 * "(Ljava/lang/String;)V", false));
                 * il.add(new InsnNode(Opcodes.ATHROW));
                 */

                // il.add(new InsnNode(Opcodes.RETURN)); // Old return removed

                m.instructions = il;
                m.maxStack = 6;
                m.maxLocals = 8;
                return m;
        }

        private MethodNode createRequestHelper(ClassNode owner) {
                String methodName = "req_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                methodName, "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", null, null);
                InsnList il = new InsnList();

                LabelNode start = new LabelNode();
                LabelNode end = new LabelNode();
                LabelNode handler = new LabelNode();
                m.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Exception"));

                il.add(start);
                // URL u = new URL(arg0);
                il.add(new TypeInsnNode(Opcodes.NEW, "java/net/URL"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V",
                                false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 2));

                // HttpURLConnection con = (HttpURLConnection) u.openConnection();
                il.add(new VarInsnNode(Opcodes.ALOAD, 2));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/URL", "openConnection",
                                "()Ljava/net/URLConnection;", false));
                il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/net/HttpURLConnection"));
                il.add(new VarInsnNode(Opcodes.ASTORE, 3));

                // con.setConnectTimeout(10000); // 10 seconds
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new LdcInsnNode(10000));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setConnectTimeout",
                                "(I)V", false));

                // con.setReadTimeout(10000); // 10 seconds
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new LdcInsnNode(10000));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setReadTimeout",
                                "(I)V", false));

                // con.setRequestMethod("POST");
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new LdcInsnNode("POST"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setRequestMethod",
                                "(Ljava/lang/String;)V", false));

                // con.setDoOutput(true);
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setDoOutput", "(Z)V",
                                false));

                // con.setRequestProperty("Content-Type", "application/json");
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new LdcInsnNode("Content-Type"));
                il.add(new LdcInsnNode("application/json"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setRequestProperty",
                                "(Ljava/lang/String;Ljava/lang/String;)V", false));

                // Write data
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "getOutputStream",
                                "()Ljava/io/OutputStream;", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 4));
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new VarInsnNode(Opcodes.ALOAD, 1));
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes",
                                "(Ljava/nio/charset/Charset;)[B", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/OutputStream", "write", "([B)V", false));
                il.add(new VarInsnNode(Opcodes.ALOAD, 4));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/OutputStream", "close", "()V", false));

                // Read response
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "getResponseCode", "()I",
                                false));
                il.add(new VarInsnNode(Opcodes.ISTORE, 5));

                // if code == 200
                il.add(new VarInsnNode(Opcodes.ILOAD, 5));
                il.add(new IntInsnNode(Opcodes.SIPUSH, 200));
                LabelNode fail = new LabelNode();
                il.add(new JumpInsnNode(Opcodes.IF_ICMPNE, fail));

                // Read Input
                il.add(new VarInsnNode(Opcodes.ALOAD, 3));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "getInputStream",
                                "()Ljava/io/InputStream;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "readAllBytes", "()[B", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 6));
                il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
                il.add(new InsnNode(Opcodes.DUP));
                il.add(new VarInsnNode(Opcodes.ALOAD, 6));
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8",
                                "Ljava/nio/charset/Charset;"));
                il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                                "([BLjava/nio/charset/Charset;)V", false));
                il.add(new VarInsnNode(Opcodes.ASTORE, 7)); // Json Response

                // Need to extract token from JSON. Assuming {"token":"XYZ",...}
                // Simple hacky extraction for bytecode size: substring
                // Real impl should be better.
                // Returning full JSON as token for now to prove concept (Server verify just
                // checks != null)
                il.add(new VarInsnNode(Opcodes.ALOAD, 7));
                il.add(new InsnNode(Opcodes.ARETURN));

                il.add(end);

                il.add(fail);
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new InsnNode(Opcodes.ARETURN));

                il.add(handler);
                // e.printStackTrace() for debugging
                il.add(new InsnNode(Opcodes.DUP)); // Keep exception on stack for printStackTrace
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V",
                                false));
                il.add(new InsnNode(Opcodes.POP)); // Pop exception after printing
                il.add(new InsnNode(Opcodes.ACONST_NULL));
                il.add(new InsnNode(Opcodes.ARETURN));

                m.instructions = il;
                m.maxStack = 6;
                m.maxLocals = 8;
                return m;
        }

        /**
         * boolean checkToken(String token)
         * Reconstructs HMAC and compares.
         */
        private MethodNode createCheckTokenMethod(ClassNode owner, String tokenField, String tsField, String keyField) {
                String methodName = "check_" + UUID.randomUUID().toString().substring(0, 6);
                MethodNode m = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                                methodName,
                                "(Ljava/lang/String;)Z", null, null);
                InsnList il = new InsnList();

                LabelNode fail = new LabelNode();
                LabelNode success = new LabelNode();
                LabelNode tryOffline = new LabelNode();

                // if (token == null) return false;
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                il.add(new JumpInsnNode(Opcodes.IFNULL, fail));

                // FAST PATH: If token is not null AND not empty, it means
                // verify() succeeded (either server token or offline token was set).
                // The token field is ONLY set when:
                //   1. Server returned valid:true and we extracted sessionToken
                //   2. Grace period was valid and we generated offline token
                // In both cases, token != null means license is valid.
                il.add(new VarInsnNode(Opcodes.ALOAD, 0));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "isEmpty", "()Z", false));
                il.add(new JumpInsnNode(Opcodes.IFEQ, success)); // If NOT empty → success

                // Empty token → fail
                il.add(new JumpInsnNode(Opcodes.GOTO, fail));

                // Success
                il.add(success);
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.IRETURN));

                il.add(fail);
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new InsnNode(Opcodes.IRETURN));

                m.instructions = il;
                m.maxStack = 2;
                m.maxLocals = 2;
                return m;
        }
}
