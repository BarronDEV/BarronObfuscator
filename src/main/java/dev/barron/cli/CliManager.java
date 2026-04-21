package dev.barron.cli;

import dev.barron.config.ObfuscationConfig;
import dev.barron.obfuscator.ObfuscationEngine;
import dev.barron.db.DatabaseManager;

import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Iterator;

public class CliManager {

    public static void run(String[] args) {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printHelp();
            return;
        }

        String command = args[0];

        try {
            switch (command) {
                case "--obfuscate":
                case "-o":
                    runObfuscation(args);
                    break;
                case "--license":
                case "-l":
                    runLicense(args);
                    break;
                default:
                    System.err.println("Unknown command: " + command);
                    printHelp();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printHelp() {
        System.out.println("Barron Obfuscator CLI");
        System.out.println("Usage:");
        System.out.println("  --obfuscate, -o [options]");
        System.out.println("    --input, -i <jar file>     Input JAR file (required)");
        System.out.println("    --output, -out <jar file>  Output JAR file (optional)");
        System.out.println("    --config, -c <json file>   Load config from JSON (optional)");
        System.out.println("    --class-enc <bool>         Enable/Disable class encryption (default: true)");
        System.out.println();
        System.out.println("  --license, -l [options]");
        System.out.println("    --gen-key                  Generate a new license key");
        System.out.println("    --days <int>               Validity days (default: 30)");
        System.out.println("    --db-host <host>           MySQL Host");
        System.out.println("    --db-user <user>           MySQL User");
        System.out.println("    --db-pass <pass>           MySQL Password");
        System.out.println("    --db-name <name>           MySQL Database");
    }

    private static void runObfuscation(String[] args) throws Exception {
        Path input = null;
        Path output = null;
        ObfuscationConfig config = new ObfuscationConfig();

        Iterator<String> it = Arrays.asList(args).iterator();
        it.next(); // skip command

        while (it.hasNext()) {
            String arg = it.next();
            switch (arg) {
                case "--input":
                case "-i":
                    if (it.hasNext())
                        input = Path.of(it.next());
                    break;
                case "--output":
                case "-out":
                    if (it.hasNext())
                        output = Path.of(it.next());
                    break;
                case "--class-enc":
                    if (it.hasNext())
                        config.setClassEncryption(Boolean.parseBoolean(it.next()));
                    break;
            }
        }

        if (input == null) {
            System.err.println("Input file is required!");
            return;
        }

        if (output == null) {
            String name = input.getFileName().toString();
            String outName = name.replace(".jar", "-protected.jar");
            output = input.getParent() == null ? Path.of(outName) : input.getParent().resolve(outName);
        }

        System.out.println("Obfuscating " + input + " -> " + output);

        ObfuscationEngine engine = new ObfuscationEngine(config);
        engine.setLogCallback(msg -> System.out.println("[OBF] " + msg));
        engine.obfuscate(input, output);

        System.out.println("Obfuscation completed successfully.");
    }

    private static void runLicense(String[] args) {
        // Basic license generation cli implementation
        DatabaseManager db = new DatabaseManager();
        int days = 30;
        String host = "localhost", user = "root", pass = "", name = "barron_licenses";
        int port = 3306;
        boolean generate = false;

        Iterator<String> it = Arrays.asList(args).iterator();
        it.next();

        while (it.hasNext()) {
            String arg = it.next();
            switch (arg) {
                case "--gen-key":
                    generate = true;
                    break;
                case "--days":
                    if (it.hasNext())
                        days = Integer.parseInt(it.next());
                    break;
                case "--db-host":
                    if (it.hasNext())
                        host = it.next();
                    break;
                case "--db-user":
                    if (it.hasNext())
                        user = it.next();
                    break;
                case "--db-pass":
                    if (it.hasNext())
                        pass = it.next();
                    break;
                case "--db-name":
                    if (it.hasNext())
                        name = it.next();
                    break;
            }
        }

        if (generate) {
            db.configure(host, port, name, user, pass);
            if (!db.connect()) {
                System.err.println("Could not connect to database!");
                return;
            }

            // CLI uses a virtual plugin name for generated keys or requires --plugin-name
            // For now let's assume valid ID 1 or lookup if implemented
            try {
                // We'll use a hardcoded 1 for now if name lookup fails or isn't provided
                // Ideally add --plugin <name> arg.
                // Let's create a placeholder method if usage is ambiguous
                // But wait, the previous code passed "cli-generated" string.
                // We need a plugin ID.
                // Let's use a dummy ID 1 or add a 'CLI-Generated' plugin if missing.
                String defaultPlugin = "CLI-Generated";
                Integer pid = db.getPluginId(defaultPlugin);
                if (pid == null) {
                    pid = db.addPlugin(defaultPlugin, "cli.jar", "1.0", "hash", "SERVER");
                }

                String key = db.createLicense(pid, days);
                System.out.println("Generated License: " + key);
            } catch (Exception e) {
                System.err.println("Error generating license: " + e.getMessage());
            }

        } else {
            System.out.println("No action specified. Use --gen-key");
        }
    }
}
