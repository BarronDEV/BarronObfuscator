package dev.barron.utils;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Smart detection of common libraries that should be excluded from obfuscation
 * Prevents breaking shaded dependencies
 */
public class LibraryDetector {

    // Known library packages - these should NOT be obfuscated
    private static final List<LibraryPattern> KNOWN_LIBRARIES = List.of(
            // Minecraft/Server APIs
            new LibraryPattern("org.bukkit.**", "Bukkit API", true),
            new LibraryPattern("net.md_5.**", "BungeeCord/Spigot", true),
            new LibraryPattern("io.papermc.**", "Paper API", true),
            new LibraryPattern("org.spigotmc.**", "Spigot API", true),
            new LibraryPattern("net.minecraft.**", "Minecraft Server", true),
            new LibraryPattern("com.mojang.**", "Mojang Libraries", true),
            new LibraryPattern("net.kyori.**", "Adventure/Kyori", true),
            new LibraryPattern("com.destroystokyo.**", "Paper Legacy", true),

            // Common shaded libraries
            new LibraryPattern("org.sqlite.**", "SQLite JDBC", false),
            new LibraryPattern("com.zaxxer.hikari.**", "HikariCP", false),
            new LibraryPattern("com.mysql.**", "MySQL Connector", false),
            new LibraryPattern("org.mariadb.**", "MariaDB Connector", false),
            new LibraryPattern("org.postgresql.**", "PostgreSQL Driver", false),
            new LibraryPattern("org.h2.**", "H2 Database", false),

            new LibraryPattern("org.bstats.**", "bStats", false),
            new LibraryPattern("org.inventivetalent.**", "InventiveTalent Libs", false),

            new LibraryPattern("com.google.gson.**", "Gson", false),
            new LibraryPattern("com.google.common.**", "Guava", false),
            new LibraryPattern("org.json.**", "JSON.org", false),
            new LibraryPattern("com.fasterxml.**", "Jackson", false),

            new LibraryPattern("org.apache.commons.**", "Apache Commons", false),
            new LibraryPattern("org.apache.http.**", "Apache HttpClient", false),
            new LibraryPattern("org.slf4j.**", "SLF4J", false),
            new LibraryPattern("org.apache.logging.**", "Log4j", false),
            new LibraryPattern("ch.qos.logback.**", "Logback", false),

            new LibraryPattern("kotlin.**", "Kotlin Runtime", false),
            new LibraryPattern("kotlinx.**", "Kotlin Extensions", false),
            new LibraryPattern("org.jetbrains.**", "JetBrains Annotations", false),

            new LibraryPattern("io.netty.**", "Netty", false),
            new LibraryPattern("com.cryptomorin.**", "XSeries", false),
            new LibraryPattern("de.tr7zw.**", "NBT API", false),
            new LibraryPattern("com.github.cryptomorin.**", "XSeries GitHub", false),

            new LibraryPattern("redis.clients.**", "Jedis/Redis", false),
            new LibraryPattern("com.rabbitmq.**", "RabbitMQ", false),
            new LibraryPattern("org.mongodb.**", "MongoDB Driver", false),

            new LibraryPattern("lombok.**", "Lombok", false),
            new LibraryPattern("javax.**", "Java Extensions", true),
            new LibraryPattern("jakarta.**", "Jakarta EE", true),

            new LibraryPattern("com.comphenix.**", "ProtocolLib", false),
            new LibraryPattern("me.clip.placeholderapi.**", "PlaceholderAPI", false),
            new LibraryPattern("net.milkbowl.vault.**", "Vault", false),
            new LibraryPattern("net.luckperms.**", "LuckPerms API", false),
            new LibraryPattern("me.lucko.**", "Lucko Libraries", false),

            // Cloud command framework
            new LibraryPattern("cloud.commandframework.**", "Cloud Commands", false),
            new LibraryPattern("org.incendo.**", "Incendo/Cloud", false));

    // Compiled patterns for efficiency
    private final List<CompiledPattern> patterns;

    public LibraryDetector() {
        this.patterns = KNOWN_LIBRARIES.stream()
                .map(lib -> new CompiledPattern(lib, compilePattern(lib.pattern)))
                .toList();
    }

    /**
     * Check if a class belongs to a known library
     */
    public LibraryMatch detectLibrary(String className) {
        String dotName = className.replace("/", ".");

        for (CompiledPattern cp : patterns) {
            if (cp.pattern.matcher(dotName).matches()) {
                return new LibraryMatch(cp.library.name, cp.library.isApi, true);
            }
        }

        return LibraryMatch.NOT_LIBRARY;
    }

    /**
     * Get all patterns for display/config
     */
    public List<String> getAllPatterns() {
        return KNOWN_LIBRARIES.stream()
                .map(lib -> lib.pattern)
                .toList();
    }

    /**
     * Get API patterns only
     */
    public List<String> getApiPatterns() {
        return KNOWN_LIBRARIES.stream()
                .filter(lib -> lib.isApi)
                .map(lib -> lib.pattern)
                .toList();
    }

    /**
     * Get library patterns (shaded dependencies)
     */
    public List<String> getLibraryPatterns() {
        return KNOWN_LIBRARIES.stream()
                .filter(lib -> !lib.isApi)
                .map(lib -> lib.pattern)
                .toList();
    }

    /**
     * Analyze a set of class names and detect libraries
     */
    public AnalysisResult analyze(Set<String> classNames) {
        Map<String, Set<String>> detectedLibraries = new LinkedHashMap<>();
        Set<String> userClasses = new LinkedHashSet<>();

        for (String className : classNames) {
            LibraryMatch match = detectLibrary(className);
            if (match.isLibrary()) {
                detectedLibraries
                        .computeIfAbsent(match.libraryName(), k -> new LinkedHashSet<>())
                        .add(className);
            } else {
                userClasses.add(className);
            }
        }

        return new AnalysisResult(detectedLibraries, userClasses);
    }

    private Pattern compilePattern(String glob) {
        String regex = glob
                .replace(".", "\\.")
                .replace("**", "##DOUBLE##")
                .replace("*", "[^.]*")
                .replace("##DOUBLE##", ".*");
        return Pattern.compile("^" + regex + "$");
    }

    private record LibraryPattern(String pattern, String name, boolean isApi) {
    }

    private record CompiledPattern(LibraryPattern library, Pattern pattern) {
    }

    public record LibraryMatch(String libraryName, boolean isApi, boolean isLibrary) {
        public static final LibraryMatch NOT_LIBRARY = new LibraryMatch(null, false, false);
    }

    public record AnalysisResult(Map<String, Set<String>> libraries, Set<String> userClasses) {
        public int getTotalLibraryClasses() {
            return libraries.values().stream().mapToInt(Set::size).sum();
        }
    }
}
