package dev.barron;

/**
 * Launcher class for JavaFX application
 * This is needed because JavaFX doesn't work properly with
 * fat JARs when the main class extends Application.
 * 
 * This workaround allows double-click execution.
 */
public class BarronLauncher {

    public static void main(String[] args) {
        Barron.main(args);
    }
}
