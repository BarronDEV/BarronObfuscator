package dev.barron.loader;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Properties;

/**
 * Bootstrap launcher for Spigot plugins.
 * This class becomes the new "main" in plugin.yml.
 * Supports both legacy (v1) and new (v2 AES-GCM) encryption.
 */
public class BarronPluginLauncher extends JavaPlugin {

    private BarronClassLoader loader;
    private Object realPlugin;
    private String realMainClass;

    @Override
    public void onLoad() {
        try {
            initLoader();
            invokeLifeCycle("onLoad");
        } catch (SecurityException e) {
            getLogger().severe("Security check failed: " + e.getMessage());
            getLogger().severe("Plugin may have been tampered with!");
            setEnabled(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onEnable() {
        try {
            if (loader == null)
                initLoader();
            invokeLifeCycle("onEnable");
        } catch (SecurityException e) {
            getLogger().severe("Security check failed: " + e.getMessage());
            setEnabled(false);
        } catch (Exception e) {
            e.printStackTrace();
            setEnabled(false);
        }
    }

    @Override
    public void onDisable() {
        try {
            invokeLifeCycle("onDisable");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initLoader() throws Exception {
        if (loader != null)
            return;

        // Read metadata to find real main class and encryption keys
        try (InputStream is = getResource("barron.meta")) {
            if (is == null) {
                throw new Exception("barron.meta not found - plugin may be corrupted");
            }

            Properties props = new Properties();
            props.load(is);

            realMainClass = props.getProperty("main");
            String key = props.getProperty("key");
            String salt = props.getProperty("salt");
            String version = props.getProperty("version", "1");
            String integrityHash = props.getProperty("integrity");

            // Choose loader based on version
            if ("2".equals(version) && salt != null) {
                // Version 2: AES-GCM with key obfuscation
                loader = new BarronClassLoader(this.getClassLoader(), key, salt, integrityHash);
            } else {
                // Version 1: Legacy XOR (backwards compatibility)
                loader = new BarronClassLoader(this.getClassLoader(), key);
            }
        }

        // Load and instantiate real plugin
        Class<?> mainClazz = loader.loadClass(realMainClass);
        realPlugin = mainClazz.getDeclaredConstructor().newInstance();
    }

    private void invokeLifeCycle(String methodName) throws Exception {
        if (realPlugin == null)
            return;
        Method method = realPlugin.getClass().getMethod(methodName);
        method.setAccessible(true);
        method.invoke(realPlugin);
    }
}
