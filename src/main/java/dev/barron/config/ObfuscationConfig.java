package dev.barron.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for obfuscation settings
 */
public class ObfuscationConfig {

    // Obfuscation levels
    public enum Level {
        OFF(0),
        LIGHT(1),
        MODERATE(2),
        AGGRESSIVE(3);

        private final int value;

        Level(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    // Feature toggles and levels
    private boolean stringEncryption = true;
    private Level stringEncryptionLevel = Level.AGGRESSIVE;

    private boolean identifierRenaming = true;
    private Level identifierRenamingLevel = Level.AGGRESSIVE;

    private boolean controlFlowObfuscation = true;
    private Level controlFlowLevel = Level.AGGRESSIVE;

    private boolean numberObfuscation = true;
    private Level numberObfuscationLevel = Level.MODERATE;

    private boolean deadCodeInjection = true;
    private Level deadCodeLevel = Level.MODERATE;

    private boolean antiDebug = true;
    private Level antiDebugLevel = Level.AGGRESSIVE;

    private boolean metadataRemoval = true;

    private boolean classEncryption = true;
    private int serverPort = 8000;
    private int webPort = 8080;

    // NEW SECURITY OPTIONS
    private boolean referenceHiding = true;
    private Level referenceHidingLevel = Level.MODERATE;

    private boolean hardcoreAntiDebug = true;

    private boolean multiLayerEncryption = true;

    private boolean selfIntegrityCheck = true;

    private boolean licenseVerification = true;

    // License key to embed into the plugin (set during obfuscation)
    private String embeddedLicenseKey = "";

    // License server URL (where the plugin will verify)
    private String licenseServerUrl = "http://localhost:8000/api/verify";

    // License server domain (for Cloudflare protection) - e.g. "api.yourdomain.com"
    // If set, this is used instead of auto-detected IP
    private String licenseServerDomain = "";

    // Load Balancer: Backup Server URL (Fallback if primary fails)
    private String backupServerUrl = "";

    // Dynamic Secret Key for Session Tokens
    private String tokenSecret = "";

    // Exclusion patterns - classes/packages to skip
    private List<String> exclusions = new ArrayList<>(List.of(
            // Minecraft/Server APIs
            "org.bukkit.**",
            "net.md_5.**",
            "io.papermc.**",
            "org.spigotmc.**",
            "net.minecraft.**",
            "com.mojang.**",
            "net.kyori.**",
            // Common shaded libraries - DO NOT OBFUSCATE
            "com.google.**",
            "org.apache.**",
            "org.slf4j.**",
            "org.json.**",
            "com.zaxxer.**",
            "org.sqlite.**",
            "com.mysql.**",
            "org.mariadb.**",
            "org.postgresql.**",
            "org.h2.**",
            "org.bstats.**",
            "kotlin.**",
            "kotlinx.**",
            "org.jetbrains.**",
            "io.netty.**",
            "com.fasterxml.**",
            "redis.clients.**",
            "org.mongodb.**",
            "de.tr7zw.**",
            "com.cryptomorin.**",
            "me.clip.placeholderapi.**",
            "net.milkbowl.vault.**",
            "net.luckperms.**",
            "com.comphenix.**",
            "javax.**",
            "jakarta.**"));

    // Keep these method names (annotations, event handlers etc)
    private List<String> keepMethodNames = new ArrayList<>(List.of(
            "onEnable",
            "onDisable",
            "onLoad",
            "onCommand",
            "onTabComplete"));

    // Getters and setters
    public boolean isStringEncryption() {
        return stringEncryption;
    }

    public void setStringEncryption(boolean v) {
        this.stringEncryption = v;
    }

    public Level getStringEncryptionLevel() {
        return stringEncryptionLevel;
    }

    public void setStringEncryptionLevel(Level v) {
        this.stringEncryptionLevel = v;
    }

    public boolean isIdentifierRenaming() {
        return identifierRenaming;
    }

    public void setIdentifierRenaming(boolean v) {
        this.identifierRenaming = v;
    }

    public Level getIdentifierRenamingLevel() {
        return identifierRenamingLevel;
    }

    public void setIdentifierRenamingLevel(Level v) {
        this.identifierRenamingLevel = v;
    }

    public boolean isControlFlowObfuscation() {
        return controlFlowObfuscation;
    }

    public void setControlFlowObfuscation(boolean v) {
        this.controlFlowObfuscation = v;
    }

    public Level getControlFlowLevel() {
        return controlFlowLevel;
    }

    public void setControlFlowLevel(Level v) {
        this.controlFlowLevel = v;
    }

    public boolean isNumberObfuscation() {
        return numberObfuscation;
    }

    public void setNumberObfuscation(boolean v) {
        this.numberObfuscation = v;
    }

    public Level getNumberObfuscationLevel() {
        return numberObfuscationLevel;
    }

    public void setNumberObfuscationLevel(Level v) {
        this.numberObfuscationLevel = v;
    }

    public boolean isDeadCodeInjection() {
        return deadCodeInjection;
    }

    public void setDeadCodeInjection(boolean v) {
        this.deadCodeInjection = v;
    }

    public Level getDeadCodeLevel() {
        return deadCodeLevel;
    }

    public void setDeadCodeLevel(Level v) {
        this.deadCodeLevel = v;
    }

    public boolean isAntiDebug() {
        return antiDebug;
    }

    public void setAntiDebug(boolean v) {
        this.antiDebug = v;
    }

    public Level getAntiDebugLevel() {
        return antiDebugLevel;
    }

    public void setAntiDebugLevel(Level v) {
        this.antiDebugLevel = v;
    }

    public boolean isMetadataRemoval() {
        return metadataRemoval;
    }

    public void setMetadataRemoval(boolean v) {
        this.metadataRemoval = v;
    }

    public boolean isClassEncryption() {
        return classEncryption;
    }

    public void setClassEncryption(boolean v) {
        this.classEncryption = v;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public int getWebPort() {
        return webPort;
    }

    public void setWebPort(int webPort) {
        this.webPort = webPort;
    }

    // NEW SECURITY OPTIONS GETTERS/SETTERS
    public boolean isReferenceHiding() {
        return referenceHiding;
    }

    public void setReferenceHiding(boolean v) {
        this.referenceHiding = v;
    }

    public Level getReferenceHidingLevel() {
        return referenceHidingLevel;
    }

    public void setReferenceHidingLevel(Level v) {
        this.referenceHidingLevel = v;
    }

    public boolean isHardcoreAntiDebug() {
        return hardcoreAntiDebug;
    }

    public void setHardcoreAntiDebug(boolean v) {
        this.hardcoreAntiDebug = v;
    }

    public boolean isMultiLayerEncryption() {
        return multiLayerEncryption;
    }

    public void setMultiLayerEncryption(boolean v) {
        this.multiLayerEncryption = v;
    }

    public boolean isSelfIntegrityCheck() {
        return selfIntegrityCheck;
    }

    public void setSelfIntegrityCheck(boolean v) {
        this.selfIntegrityCheck = v;
    }

    public boolean isLicenseVerification() {
        return licenseVerification;
    }

    public void setLicenseVerification(boolean v) {
        this.licenseVerification = v;
    }

    public String getEmbeddedLicenseKey() {
        return embeddedLicenseKey;
    }

    public void setEmbeddedLicenseKey(String key) {
        this.embeddedLicenseKey = key;
    }

    public String getLicenseServerUrl() {
        return licenseServerUrl;
    }

    public void setLicenseServerUrl(String url) {
        this.licenseServerUrl = url;
    }

    public String getLicenseServerDomain() {
        return licenseServerDomain;
    }

    public void setLicenseServerDomain(String domain) {
        this.licenseServerDomain = domain;
    }

    public String getBackupServerUrl() {
        return backupServerUrl;
    }

    public void setBackupServerUrl(String url) {
        this.backupServerUrl = url;
    }

    public String getTokenSecret() {
        return tokenSecret;
    }

    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    public List<String> getExclusions() {
        return exclusions;
    }

    public void setExclusions(List<String> v) {
        this.exclusions = v;
    }

    public List<String> getKeepMethodNames() {
        return keepMethodNames;
    }

    public void setKeepMethodNames(List<String> v) {
        this.keepMethodNames = v;
    }

    /**
     * Check if a class should be excluded from obfuscation
     */
    public boolean isExcluded(String className) {
        for (String pattern : exclusions) {
            if (matchesPattern(className, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a method name should be kept
     */
    public boolean shouldKeepMethodName(String methodName) {
        return keepMethodNames.contains(methodName);
    }

    private boolean matchesPattern(String className, String pattern) {
        // Convert pattern to regex
        String regex = pattern
                .replace(".", "\\.")
                .replace("**", "##DOUBLESTAR##")
                .replace("*", "[^.]*")
                .replace("##DOUBLESTAR##", ".*");
        return className.matches(regex);
    }
}
