package dev.barron;

import dev.barron.gui.MainWindow;
import javafx.application.Application;

import java.util.prefs.Preferences;

/**
 * Barron Java Obfuscator v2.0
 * Professional-grade obfuscation with extreme randomization
 * 
 * Features:
 * - AES-256-GCM + Multi-layer string encryption
 * - Extreme randomization (different output every run)
 * - Anti-debug (6-layer detection)
 * - Reference hiding (reflection-based)
 * - Dead code injection
 */
public class Barron {

    public static final String VERSION = "2.0.0";
    public static final String NAME = "Barron Obfuscator";

    public static void main(String[] args) {
        // Check for CLI args or headless environment
        boolean isHeadless = Boolean.getBoolean("java.awt.headless");
        boolean hasArgs = args.length > 0;

        // Start License Server with saved preferences
        int port = Integer.parseInt(Preferences.userNodeForPackage(dev.barron.gui.MainWindow.class)
                .get("server.port", "8000"));
        int webPort = Integer.parseInt(Preferences.userNodeForPackage(dev.barron.gui.MainWindow.class)
                .get("server.web_port", "8080"));

        System.out.println("Starting Servers on Ports: API=" + port + ", Web=" + webPort);
        dev.barron.server.LicenseServer.start(new dev.barron.db.DatabaseManager(), port, webPort);

        if (isHeadless || hasArgs) {
            System.out.println("Running in CLI Mode...");
            dev.barron.cli.CliManager.run(args);
            return;
        }

        System.out.println("╔════════════════════════════════════════════════════╗");
        System.out.println("║          " + NAME + " v" + VERSION + "             ║");
        System.out.println("║     Professional Java Obfuscation Suite            ║");
        System.out.println("╠════════════════════════════════════════════════════╣");
        System.out.println("║  Features:                                         ║");
        System.out.println("║  • AES-256-GCM Multi-layer Encryption              ║");
        System.out.println("║  • Extreme Randomization Engine                    ║");
        System.out.println("║  • 6-Layer Anti-Debug Protection                   ║");
        System.out.println("║  • Reference Hiding via Reflection                 ║");
        System.out.println("║  • Dynamic Dead Code Injection                     ║");
        System.out.println("╚════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            Application.launch(MainWindow.class, args);
        } catch (Throwable t) {
            System.err.println("GUI failed to start: " + t.getMessage());
            System.err.println("Falling back to Headless Server Mode. Application will stay running.");

            // Keep alive for License Server
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
