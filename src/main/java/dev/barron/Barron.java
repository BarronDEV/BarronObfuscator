package dev.barron;

import dev.barron.gui.MainWindow;
import javafx.application.Application;

/**
 * Barron Java Obfuscator v2.0
 * Professional-grade obfuscation with extreme randomization
 * 
 * Features:
 * - AES-256-GCM + Multi-layer string encryption
 * - Extreme randomization (different output every run)
 * - Advanced anti-debug (6-layer detection)
 * - Reference hiding (reflection-based)
 * - Dead code injection (2-15 methods, 5-25 instructions each)
 */
public class Barron {

    public static final String VERSION = "2.0.0";
    public static final String NAME = "Barron Obfuscator";

    public static void main(String[] args) {
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

        Application.launch(MainWindow.class, args);
    }
}
