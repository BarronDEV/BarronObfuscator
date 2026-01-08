package dev.barron.license;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Base64;

/**
 * Generates the License Server application files
 * 
 * This creates:
 * - Complete Java server application source
 * - Build script (Gradle)
 * - KURULUM.txt with setup instructions
 */
public class ServerAppGenerator {

    public static void generate(Path outputDir) throws IOException {
        // Create directories
        Files.createDirectories(outputDir);
        Path srcDir = outputDir.resolve("src/main/java/dev/barron/server");
        Files.createDirectories(srcDir);
        Path guiDir = outputDir.resolve("src/main/java/dev/barron/server/gui");
        Files.createDirectories(guiDir);
        Path cryptoDir = outputDir.resolve("src/main/java/dev/barron/server/crypto");
        Files.createDirectories(cryptoDir);

        // Generate main files
        writeFile(outputDir.resolve("build.gradle"), generateBuildGradle());
        writeFile(outputDir.resolve("settings.gradle"), "rootProject.name = 'barron-license-server'\n");
        writeFile(outputDir.resolve("KURULUM.txt"), generateKurulumTxt());

        // Generate Java source files
        writeFile(srcDir.resolve("LicenseServerMain.java"), generateMainClass());
        writeFile(guiDir.resolve("ServerWindow.java"), generateServerWindow());
        writeFile(cryptoDir.resolve("KeyManager.java"), generateKeyManager());
        writeFile(srcDir.resolve("LicenseDatabase.java"), generateDatabase());
        writeFile(srcDir.resolve("LicenseAPI.java"), generateAPI());
    }

    private static void writeFile(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }

    private static String generateBuildGradle() {
        return """
                plugins {
                    id 'java'
                    id 'application'
                    id 'org.openjfx.javafxplugin' version '0.1.0'
                }

                group = 'dev.barron.server'
                version = '1.0.0'

                repositories {
                    mavenCentral()
                }

                java {
                    toolchain {
                        languageVersion = JavaLanguageVersion.of(21)
                    }
                }

                javafx {
                    version = '21.0.1'
                    modules = ['javafx.controls']
                }

                dependencies {
                    // SQLite for license database
                    implementation 'org.xerial:sqlite-jdbc:3.44.1.0'

                    // Jetty for HTTP server
                    implementation 'org.eclipse.jetty:jetty-server:11.0.18'
                    implementation 'org.eclipse.jetty:jetty-servlet:11.0.18'

                    // JSON
                    implementation 'com.google.code.gson:gson:2.10.1'
                }

                application {
                    mainClass = 'dev.barron.server.LicenseServerMain'
                }

                jar {
                    manifest {
                        attributes(
                            'Main-Class': 'dev.barron.server.LicenseServerMain'
                        )
                    }
                    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
                    from {
                        configurations.runtimeClasspath.collect { it.isDirectory() ? it : zipTree(it) }
                    }
                    exclude 'module-info.class'
                    archiveBaseName = 'Barron-License-Server'
                }

                // Create native exe
                task createExe(type: Exec, dependsOn: jar) {
                    def outputDir = file("${buildDir}/native")
                    doFirst { outputDir.mkdirs() }
                    commandLine 'jpackage',
                        '--type', 'app-image',
                        '--name', 'Barron License Server',
                        '--input', "${buildDir}/libs",
                        '--main-jar', "Barron-License-Server-${version}.jar",
                        '--main-class', 'dev.barron.server.LicenseServerMain',
                        '--dest', outputDir.absolutePath,
                        '--app-version', version
                }
                """;
    }

    private static String generateKurulumTxt() {
        return """
                ═══════════════════════════════════════════════════════════════════
                         BARRON LICENSE SERVER - KURULUM KILAVUZU
                ═══════════════════════════════════════════════════════════════════

                Bu sunucu, şifreleme anahtarlarını güvenli bir şekilde saklar ve
                istemcilere tek yönlü, şifreli bir kanal üzerinden iletir.

                ───────────────────────────────────────────────────────────────────
                1. GEREKSİNİMLER
                ───────────────────────────────────────────────────────────────────

                • Java 21 veya üzeri
                • Gradle (otomatik indirilir)
                • 7742 portu açık olmalı

                ───────────────────────────────────────────────────────────────────
                2. DERLEME VE ÇALIŞTIRMA
                ───────────────────────────────────────────────────────────────────

                A) JAR olarak çalıştırma:
                   1. Terminal/CMD açın
                   2. Bu klasöre gidin
                   3. Çalıştırın:

                      gradle jar
                      java -jar build/libs/Barron-License-Server-1.0.0.jar

                B) Native EXE olarak derleme:
                   1. Terminal/CMD açın
                   2. Bu klasöre gidin
                   3. Çalıştırın:

                      gradle createExe

                   4. Çıktı: build/native/Barron License Server/

                ───────────────────────────────────────────────────────────────────
                3. LİSANS OLUŞTURMA
                ───────────────────────────────────────────────────────────────────

                1. Sunucu uygulamasını çalıştırın
                2. "Yeni Lisans Oluştur" butonuna tıklayın
                3. Oluşturulan lisans anahtarını kopyalayın
                4. Bu anahtarı müşterilerinize verin

                ───────────────────────────────────────────────────────────────────
                4. GÜVENLİK MİMARİSİ
                ───────────────────────────────────────────────────────────────────

                Haberleşme Protokolü:

                ┌───────────────────────────────────────────────────────────────┐
                │  1. İstemci → Sunucu: ECDH Public Key + Lisans ID            │
                │  2. Sunucu → İstemci: ECDH Public Key + Challenge             │
                │  3. İstemci → Sunucu: Challenge Yanıtı (imzalı)               │
                │  4. Sunucu → İstemci: Şifreli Master Key (tek seferlik)      │
                │  5. Sunucu oturumu SİLER                                      │
                └───────────────────────────────────────────────────────────────┘

                • Anahtarlar sunucuda şifrelenmiş olarak saklanır
                • Her obfuscation için benzersiz parametreler üretilir
                • ECDH P-384 + AES-256-GCM kullanılır
                • Man-in-the-middle saldırısına karşı koruma sağlanır

                ───────────────────────────────────────────────────────────────────
                5. ÖNERİLER
                ───────────────────────────────────────────────────────────────────

                ✓ Sunucuyu SSL/TLS sertifikası ile çalıştırın (HTTPS)
                ✓ Güvenlik duvarında sadece 7742 portunu açın
                ✓ Düzenli yedekler alın (licenses.db)
                ✓ Sunucu loglarını izleyin

                ───────────────────────────────────────────────────────────────────
                6. PORT AYARLARI
                ───────────────────────────────────────────────────────────────────

                Varsayılan port: 7742
                Değiştirmek için: Sunucu GUI'sinde "Ayarlar" bölümüne gidin

                ═══════════════════════════════════════════════════════════════════
                Destek: github.com/barron-obfuscator
                ═══════════════════════════════════════════════════════════════════
                """;
    }

    private static String generateMainClass() {
        return """
                package dev.barron.server;

                import dev.barron.server.gui.ServerWindow;
                import javafx.application.Application;

                /**
                 * Barron License Server
                 * Secure key storage for maximum obfuscation protection
                 */
                public class LicenseServerMain {

                    public static final String VERSION = "1.0.0";
                    public static final String NAME = "Barron License Server";
                    public static final int DEFAULT_PORT = 7742;

                    public static void main(String[] args) {
                        System.out.println("╔════════════════════════════════════════════════════╗");
                        System.out.println("║        " + NAME + " v" + VERSION + "           ║");
                        System.out.println("╠════════════════════════════════════════════════════╣");
                        System.out.println("║  Secure Key Storage for Maximum Protection         ║");
                        System.out.println("╚════════════════════════════════════════════════════╝");

                        Application.launch(ServerWindow.class, args);
                    }
                }
                """;
    }

    private static String generateServerWindow() {
        return """
                package dev.barron.server.gui;

                import dev.barron.server.LicenseServerMain;
                import dev.barron.server.LicenseDatabase;
                import dev.barron.server.LicenseAPI;
                import javafx.application.Application;
                import javafx.application.Platform;
                import javafx.geometry.Insets;
                import javafx.geometry.Pos;
                import javafx.scene.Scene;
                import javafx.scene.control.*;
                import javafx.scene.layout.*;
                import javafx.scene.paint.Color;
                import javafx.scene.text.Font;
                import javafx.scene.text.FontWeight;
                import javafx.stage.Stage;

                import java.time.LocalDateTime;
                import java.time.format.DateTimeFormatter;
                import java.util.UUID;

                public class ServerWindow extends Application {

                    private LicenseDatabase database;
                    private LicenseAPI api;
                    private TextArea logArea;
                    private ListView<String> licenseList;
                    private Label statusLabel;
                    private Button startButton;
                    private boolean serverRunning = false;
                    private int port = LicenseServerMain.DEFAULT_PORT;

                    @Override
                    public void start(Stage stage) {
                        database = new LicenseDatabase();

                        stage.setTitle(LicenseServerMain.NAME + " v" + LicenseServerMain.VERSION);
                        stage.setMinWidth(700);
                        stage.setMinHeight(600);

                        VBox root = new VBox(15);
                        root.setPadding(new Insets(20));
                        root.setStyle("-fx-background-color: #1a1a2e;");

                        // Header
                        Label header = new Label("🔐 BARRON LICENSE SERVER");
                        header.setFont(Font.font("Segoe UI", FontWeight.BOLD, 22));
                        header.setTextFill(Color.web("#00ff88"));

                        // Status bar
                        HBox statusBar = createStatusBar();

                        // License management panel
                        VBox licensePanel = createLicensePanel();

                        // Log area
                        VBox logPanel = createLogPanel();

                        root.getChildren().addAll(header, statusBar, licensePanel, logPanel);
                        VBox.setVgrow(logPanel, Priority.ALWAYS);

                        Scene scene = new Scene(root, 750, 650);
                        stage.setScene(scene);
                        stage.show();

                        log("Sunucu başlatıldı");
                        log("Varsayılan port: " + port);
                        refreshLicenseList();
                    }

                    private HBox createStatusBar() {
                        statusLabel = new Label("⚫ Durduruldu");
                        statusLabel.setTextFill(Color.web("#ff4444"));
                        statusLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));

                        Label portLabel = new Label("Port:");
                        portLabel.setTextFill(Color.web("#8892b0"));
                        TextField portField = new TextField(String.valueOf(port));
                        portField.setPrefWidth(80);
                        portField.setStyle("-fx-background-color: #0f0f23; -fx-text-fill: #00ff88;");

                        startButton = new Button("▶ Sunucuyu Başlat");
                        startButton.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white; -fx-font-weight: bold;");
                        startButton.setOnAction(e -> {
                            if (serverRunning) {
                                stopServer();
                            } else {
                                try {
                                    port = Integer.parseInt(portField.getText());
                                } catch (NumberFormatException ex) {
                                    port = LicenseServerMain.DEFAULT_PORT;
                                }
                                startServer();
                            }
                        });

                        HBox box = new HBox(15, statusLabel, new Region(), portLabel, portField, startButton);
                        HBox.setHgrow(box.getChildren().get(1), Priority.ALWAYS);
                        box.setAlignment(Pos.CENTER_LEFT);
                        box.setPadding(new Insets(10));
                        box.setStyle("-fx-background-color: #16213e; -fx-background-radius: 10;");

                        return box;
                    }

                    private VBox createLicensePanel() {
                        Label title = new Label("📋 Lisanslar");
                        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
                        title.setTextFill(Color.web("#e94560"));

                        licenseList = new ListView<>();
                        licenseList.setPrefHeight(150);
                        licenseList.setStyle("-fx-background-color: #0f0f23;");

                        Button createBtn = new Button("➕ Yeni Lisans Oluştur");
                        createBtn.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white;");
                        createBtn.setOnAction(e -> createNewLicense());

                        Button deleteBtn = new Button("🗑️ Seçili Lisansı Sil");
                        deleteBtn.setStyle("-fx-background-color: #dd3333; -fx-text-fill: white;");
                        deleteBtn.setOnAction(e -> deleteSelectedLicense());

                        Button copyBtn = new Button("📋 Anahtarı Kopyala");
                        copyBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
                        copyBtn.setOnAction(e -> copySelectedLicense());

                        HBox buttons = new HBox(10, createBtn, deleteBtn, copyBtn);

                        VBox panel = new VBox(10, title, licenseList, buttons);
                        panel.setPadding(new Insets(10));
                        panel.setStyle("-fx-background-color: #16213e; -fx-background-radius: 10;");

                        return panel;
                    }

                    private VBox createLogPanel() {
                        Label title = new Label("📋 Sunucu Logları");
                        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
                        title.setTextFill(Color.web("#8892b0"));

                        logArea = new TextArea();
                        logArea.setEditable(false);
                        logArea.setStyle("-fx-control-inner-background: #0f0f23; -fx-text-fill: #00ff88;");

                        VBox panel = new VBox(5, title, logArea);
                        VBox.setVgrow(logArea, Priority.ALWAYS);
                        return panel;
                    }

                    private void startServer() {
                        log("Sunucu başlatılıyor (port: " + port + ")...");
                        try {
                            api = new LicenseAPI(database, port);
                            api.start();
                            serverRunning = true;
                            statusLabel.setText("🟢 Çalışıyor (:" + port + ")");
                            statusLabel.setTextFill(Color.web("#00ff88"));
                            startButton.setText("⏹ Sunucuyu Durdur");
                            startButton.setStyle("-fx-background-color: #dd3333; -fx-text-fill: white; -fx-font-weight: bold;");
                            log("✅ Sunucu başarıyla başlatıldı!");
                        } catch (Exception e) {
                            log("❌ Sunucu başlatılamadı: " + e.getMessage());
                        }
                    }

                    private void stopServer() {
                        log("Sunucu durduruluyor...");
                        try {
                            if (api != null) api.stop();
                            serverRunning = false;
                            statusLabel.setText("⚫ Durduruldu");
                            statusLabel.setTextFill(Color.web("#ff4444"));
                            startButton.setText("▶ Sunucuyu Başlat");
                            startButton.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white; -fx-font-weight: bold;");
                            log("Sunucu durduruldu.");
                        } catch (Exception e) {
                            log("❌ Durdurma hatası: " + e.getMessage());
                        }
                    }

                    private void createNewLicense() {
                        String key = generateLicenseKey();
                        database.createLicense(key);
                        refreshLicenseList();
                        log("✅ Yeni lisans oluşturuldu: " + key);

                        Alert alert = new Alert(Alert.AlertType.INFORMATION);
                        alert.setTitle("Lisans Oluşturuldu");
                        alert.setHeaderText("Yeni lisans anahtarı:");
                        alert.setContentText(key);
                        alert.showAndWait();
                    }

                    private void deleteSelectedLicense() {
                        String selected = licenseList.getSelectionModel().getSelectedItem();
                        if (selected != null) {
                            String key = selected.split(" ")[0];
                            database.deleteLicense(key);
                            refreshLicenseList();
                            log("🗑️ Lisans silindi: " + key);
                        }
                    }

                    private void copySelectedLicense() {
                        String selected = licenseList.getSelectionModel().getSelectedItem();
                        if (selected != null) {
                            String key = selected.split(" ")[0];
                            javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
                            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
                            content.putString(key);
                            clipboard.setContent(content);
                            log("📋 Anahtar panoya kopyalandı");
                        }
                    }

                    private void refreshLicenseList() {
                        licenseList.getItems().clear();
                        for (String license : database.getAllLicenses()) {
                            licenseList.getItems().add(license);
                        }
                    }

                    private String generateLicenseKey() {
                        String uuid = UUID.randomUUID().toString().toUpperCase();
                        return uuid.substring(0, 8) + "-" + uuid.substring(9, 13) + "-" +
                               uuid.substring(14, 18) + "-" + uuid.substring(19, 23);
                    }

                    private void log(String message) {
                        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                        Platform.runLater(() -> {
                            logArea.appendText("[" + timestamp + "] " + message + "\\n");
                        });
                    }
                }
                """;
    }

    private static String generateKeyManager() {
        return """
                package dev.barron.server.crypto;

                import javax.crypto.*;
                import javax.crypto.spec.GCMParameterSpec;
                import javax.crypto.spec.SecretKeySpec;
                import java.security.*;
                import java.security.spec.ECGenParameterSpec;
                import java.util.Base64;

                /**
                 * Manages cryptographic operations for the license server
                 */
                public class KeyManager {

                    private static final String CURVE = "secp384r1";
                    private static final int GCM_IV_LENGTH = 12;
                    private static final int GCM_TAG_LENGTH = 128;

                    private KeyPair serverKeyPair;
                    private final SecureRandom secureRandom = new SecureRandom();

                    public KeyManager() {
                        try {
                            serverKeyPair = generateECDHKeyPair();
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to initialize KeyManager", e);
                        }
                    }

                    public KeyPair generateECDHKeyPair() throws Exception {
                        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
                        keyGen.initialize(ecSpec, secureRandom);
                        return keyGen.generateKeyPair();
                    }

                    public byte[] getServerPublicKey() {
                        return serverKeyPair.getPublic().getEncoded();
                    }

                    public byte[] deriveSharedSecret(byte[] clientPublicKeyBytes) throws Exception {
                        KeyFactory keyFactory = KeyFactory.getInstance("EC");
                        java.security.spec.X509EncodedKeySpec keySpec =
                                new java.security.spec.X509EncodedKeySpec(clientPublicKeyBytes);
                        PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

                        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
                        keyAgreement.init(serverKeyPair.getPrivate());
                        keyAgreement.doPhase(clientPublicKey, true);

                        byte[] secret = keyAgreement.generateSecret();
                        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                        return sha256.digest(secret);
                    }

                    public byte[] generateChallenge() {
                        byte[] challenge = new byte[32];
                        secureRandom.nextBytes(challenge);
                        return challenge;
                    }

                    public boolean verifyChallenge(byte[] challenge, byte[] response, byte[] sharedSecret)
                            throws Exception {
                        Mac hmac = Mac.getInstance("HmacSHA256");
                        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "HmacSHA256");
                        hmac.init(keySpec);
                        byte[] expected = hmac.doFinal(challenge);
                        return MessageDigest.isEqual(expected, response);
                    }

                    public byte[] encryptData(byte[] data, byte[] key) throws Exception {
                        byte[] iv = new byte[GCM_IV_LENGTH];
                        secureRandom.nextBytes(iv);

                        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

                        byte[] ciphertext = cipher.doFinal(data);

                        // Prepend IV to ciphertext
                        byte[] result = new byte[iv.length + ciphertext.length];
                        System.arraycopy(iv, 0, result, 0, iv.length);
                        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

                        return result;
                    }
                }
                """;
    }

    private static String generateDatabase() {
        return """
                package dev.barron.server;

                import java.sql.*;
                import java.security.SecureRandom;
                import java.util.*;

                /**
                 * SQLite database for license management
                 */
                public class LicenseDatabase {

                    private static final String DB_URL = "jdbc:sqlite:licenses.db";
                    private final SecureRandom random = new SecureRandom();

                    public LicenseDatabase() {
                        initDatabase();
                    }

                    private void initDatabase() {
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             Statement stmt = conn.createStatement()) {

                            // Create licenses table
                            stmt.execute(\"\"\"
                                CREATE TABLE IF NOT EXISTS licenses (
                                    license_key TEXT PRIMARY KEY,
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                    last_used TIMESTAMP,
                                    use_count INTEGER DEFAULT 0,
                                    master_key BLOB,
                                    substitution_table BLOB,
                                    xor_layer_count INTEGER,
                                    pbkdf2_iterations INTEGER,
                                    salt BLOB,
                                    algorithm_variant INTEGER,
                                    active INTEGER DEFAULT 1
                                )\"\"\");

                        } catch (SQLException e) {
                            e.printStackTrace();
                        }
                    }

                    public void createLicense(String licenseKey) {
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             PreparedStatement stmt = conn.prepareStatement(
                                 "INSERT INTO licenses (license_key, master_key, substitution_table, " +
                                 "xor_layer_count, pbkdf2_iterations, salt, algorithm_variant) VALUES (?,?,?,?,?,?,?)")) {

                            byte[] masterKey = new byte[32];
                            random.nextBytes(masterKey);

                            byte[] substitutionTable = new byte[256];
                            for (int i = 0; i < 256; i++) substitutionTable[i] = (byte) i;
                            for (int i = 255; i > 0; i--) {
                                int j = random.nextInt(i + 1);
                                byte temp = substitutionTable[i];
                                substitutionTable[i] = substitutionTable[j];
                                substitutionTable[j] = temp;
                            }

                            byte[] salt = new byte[32];
                            random.nextBytes(salt);

                            stmt.setString(1, licenseKey);
                            stmt.setBytes(2, masterKey);
                            stmt.setBytes(3, substitutionTable);
                            stmt.setInt(4, 3 + random.nextInt(8));
                            stmt.setInt(5, 10000 + random.nextInt(90000));
                            stmt.setBytes(6, salt);
                            stmt.setInt(7, random.nextInt(16));
                            stmt.executeUpdate();

                        } catch (SQLException e) {
                            e.printStackTrace();
                        }
                    }

                    public void deleteLicense(String licenseKey) {
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             PreparedStatement stmt = conn.prepareStatement(
                                 "DELETE FROM licenses WHERE license_key = ?")) {
                            stmt.setString(1, licenseKey);
                            stmt.executeUpdate();
                        } catch (SQLException e) {
                            e.printStackTrace();
                        }
                    }

                    public List<String> getAllLicenses() {
                        List<String> licenses = new ArrayList<>();
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             Statement stmt = conn.createStatement();
                             ResultSet rs = stmt.executeQuery(
                                 "SELECT license_key, created_at, use_count FROM licenses WHERE active = 1")) {
                            while (rs.next()) {
                                licenses.add(rs.getString("license_key") +
                                    " (Kullanım: " + rs.getInt("use_count") + ")");
                            }
                        } catch (SQLException e) {
                            e.printStackTrace();
                        }
                        return licenses;
                    }

                    public boolean isValidLicense(String licenseKey) {
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             PreparedStatement stmt = conn.prepareStatement(
                                 "SELECT active FROM licenses WHERE license_key = ?")) {
                            stmt.setString(1, licenseKey);
                            ResultSet rs = stmt.executeQuery();
                            return rs.next() && rs.getInt("active") == 1;
                        } catch (SQLException e) {
                            return false;
                        }
                    }

                    public byte[] getLicenseKeyBundle(String licenseKey) {
                        try (Connection conn = DriverManager.getConnection(DB_URL);
                             PreparedStatement stmt = conn.prepareStatement(
                                 "SELECT * FROM licenses WHERE license_key = ? AND active = 1")) {
                            stmt.setString(1, licenseKey);
                            ResultSet rs = stmt.executeQuery();
                            if (rs.next()) {
                                // Update use count
                                try (PreparedStatement update = conn.prepareStatement(
                                    "UPDATE licenses SET use_count = use_count + 1, last_used = CURRENT_TIMESTAMP WHERE license_key = ?")) {
                                    update.setString(1, licenseKey);
                                    update.executeUpdate();
                                }
                                // Return serialized key bundle
                                return serializeKeyBundle(rs);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }

                    private byte[] serializeKeyBundle(ResultSet rs) throws SQLException {
                        // Simple serialization
                        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                        java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
                        try {
                            byte[] masterKey = rs.getBytes("master_key");
                            byte[] substitutionTable = rs.getBytes("substitution_table");
                            byte[] salt = rs.getBytes("salt");

                            dos.writeInt(masterKey.length);
                            dos.write(masterKey);
                            dos.writeInt(substitutionTable.length);
                            dos.write(substitutionTable);
                            dos.writeInt(rs.getInt("xor_layer_count"));
                            dos.writeInt(rs.getInt("pbkdf2_iterations"));
                            dos.writeInt(salt.length);
                            dos.write(salt);
                            dos.writeInt(rs.getInt("algorithm_variant"));
                            dos.flush();
                            return baos.toByteArray();
                        } catch (java.io.IOException e) {
                            throw new SQLException("Serialization error", e);
                        }
                    }
                }
                """;
    }

    private static String generateAPI() {
        return """
                package dev.barron.server;

                import dev.barron.server.crypto.KeyManager;
                import com.sun.net.httpserver.*;
                import java.io.*;
                import java.net.InetSocketAddress;
                import java.nio.charset.StandardCharsets;
                import java.util.*;
                import java.util.concurrent.ConcurrentHashMap;

                /**
                 * HTTP API for license key distribution
                 */
                public class LicenseAPI {

                    private final LicenseDatabase database;
                    private final KeyManager keyManager;
                    private final int port;
                    private HttpServer server;

                    // Session storage (sessionId -> session data)
                    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

                    public LicenseAPI(LicenseDatabase database, int port) {
                        this.database = database;
                        this.keyManager = new KeyManager();
                        this.port = port;
                    }

                    public void start() throws IOException {
                        server = HttpServer.create(new InetSocketAddress(port), 0);
                        server.createContext("/api/handshake", this::handleHandshake);
                        server.createContext("/api/keys", this::handleKeys);
                        server.createContext("/api/test", this::handleTest);
                        server.setExecutor(null);
                        server.start();
                    }

                    public void stop() {
                        if (server != null) {
                            server.stop(0);
                        }
                    }

                    private void handleTest(HttpExchange exchange) throws IOException {
                        String response = "{\\"status\\":\\"ok\\",\\"version\\":\\"1.0.0\\"}";
                        exchange.sendResponseHeaders(200, response.length());
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(response.getBytes(StandardCharsets.UTF_8));
                        }
                    }

                    private void handleHandshake(HttpExchange exchange) throws IOException {
                        if (!"POST".equals(exchange.getRequestMethod())) {
                            sendError(exchange, 405, "Method not allowed");
                            return;
                        }

                        String licenseKey = exchange.getRequestHeaders().getFirst("X-License-Key");
                        if (licenseKey == null || !database.isValidLicense(licenseKey)) {
                            sendError(exchange, 401, "Invalid license");
                            return;
                        }

                        try {
                            // Read client public key
                            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                            String clientPubKeyB64 = extractJsonValue(body, "publicKey");
                            byte[] clientPublicKey = Base64.getDecoder().decode(clientPubKeyB64);

                            // Generate challenge
                            byte[] challenge = keyManager.generateChallenge();

                            // Derive shared secret
                            byte[] sharedSecret = keyManager.deriveSharedSecret(clientPublicKey);

                            // Create session
                            String sessionId = UUID.randomUUID().toString();
                            Session session = new Session();
                            session.licenseKey = licenseKey;
                            session.challenge = challenge;
                            session.sharedSecret = sharedSecret;
                            session.createdAt = System.currentTimeMillis();
                            sessions.put(sessionId, session);

                            // Send response
                            String response = String.format(
                                "{\\"serverPublicKey\\":\\"%s\\",\\"challenge\\":\\"%s\\",\\"sessionId\\":\\"%s\\"}",
                                Base64.getEncoder().encodeToString(keyManager.getServerPublicKey()),
                                Base64.getEncoder().encodeToString(challenge),
                                sessionId
                            );

                            exchange.sendResponseHeaders(200, response.length());
                            try (OutputStream os = exchange.getResponseBody()) {
                                os.write(response.getBytes(StandardCharsets.UTF_8));
                            }

                        } catch (Exception e) {
                            sendError(exchange, 500, "Handshake error: " + e.getMessage());
                        }
                    }

                    private void handleKeys(HttpExchange exchange) throws IOException {
                        if (!"POST".equals(exchange.getRequestMethod())) {
                            sendError(exchange, 405, "Method not allowed");
                            return;
                        }

                        String sessionId = exchange.getRequestHeaders().getFirst("X-Session-Id");
                        Session session = sessions.get(sessionId);

                        if (session == null) {
                            sendError(exchange, 401, "Invalid session");
                            return;
                        }

                        // Session is one-time use - remove immediately
                        sessions.remove(sessionId);

                        try {
                            // Read challenge response
                            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                            String responseB64 = extractJsonValue(body, "challengeResponse");
                            byte[] challengeResponse = Base64.getDecoder().decode(responseB64);

                            // Verify challenge
                            if (!keyManager.verifyChallenge(session.challenge, challengeResponse, session.sharedSecret)) {
                                sendError(exchange, 401, "Challenge verification failed");
                                return;
                            }

                            // Get key bundle
                            byte[] keyBundle = database.getLicenseKeyBundle(session.licenseKey);
                            if (keyBundle == null) {
                                sendError(exchange, 404, "License not found");
                                return;
                            }

                            // Encrypt key bundle
                            byte[] encryptedKeys = keyManager.encryptData(keyBundle, session.sharedSecret);

                            // Send encrypted keys
                            String response = String.format(
                                "{\\"encryptedKeys\\":\\"%s\\"}",
                                Base64.getEncoder().encodeToString(encryptedKeys)
                            );

                            exchange.sendResponseHeaders(200, response.length());
                            try (OutputStream os = exchange.getResponseBody()) {
                                os.write(response.getBytes(StandardCharsets.UTF_8));
                            }

                        } catch (Exception e) {
                            sendError(exchange, 500, "Key retrieval error: " + e.getMessage());
                        }
                    }

                    private void sendError(HttpExchange exchange, int code, String message) throws IOException {
                        String response = "{\\"error\\":\\"" + message + "\\"}";
                        exchange.sendResponseHeaders(code, response.length());
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(response.getBytes(StandardCharsets.UTF_8));
                        }
                    }

                    private String extractJsonValue(String json, String key) {
                        int keyIndex = json.indexOf("\\"" + key + "\\"");
                        if (keyIndex == -1) return "";
                        int valueStart = json.indexOf("\\"", keyIndex + key.length() + 3) + 1;
                        int valueEnd = json.indexOf("\\"", valueStart);
                        return json.substring(valueStart, valueEnd);
                    }

                    private static class Session {
                        String licenseKey;
                        byte[] challenge;
                        byte[] sharedSecret;
                        long createdAt;
                    }
                }
                """;
    }
}
