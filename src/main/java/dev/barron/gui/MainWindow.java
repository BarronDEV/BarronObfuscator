package dev.barron.gui;

import dev.barron.Barron;
import dev.barron.config.ObfuscationConfig;
import dev.barron.db.DatabaseManager;
import dev.barron.i18n.I18n;
import dev.barron.obfuscator.ObfuscationEngine;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Rectangle;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.prefs.Preferences;
import java.sql.SQLException;

/**
 * Barron License Manager - 4 Page Application
 * 
 * Page 2: License Generation
 * Page 3: License Management
 * Page 4: Settings (Language, MySQL, Load Balancer)
 */
public class MainWindow extends Application {

    // Static instance for global logging
    private static MainWindow instance;

    private Stage primaryStage;
    private ObfuscationConfig config;
    private DatabaseManager database;
    private Preferences prefs;

    /**
     * Global log method for external components to write to GUI log
     */
    public static void globalLog(String message) {
        if (instance != null) {
            instance.log(message);
        } else {
            System.out.println(message); // Fallback to console
        }
    }

    // Current state
    private File selectedJar;
    private boolean serverModeEnabled = true;

    // UI Components
    private TextArea logArea;
    private TabPane tabPane;
    private TableView<DatabaseManager.LicenseInfo> licenseTable;
    private ListView<DatabaseManager.PluginInfo> pluginList;

    // Page 1 components
    private Label dropLabel;
    private ToggleButton normalModeBtn;
    private ToggleButton serverModeBtn;
    private CheckBox stringEncryptionCheck, identifierRenamingCheck, controlFlowCheck;
    private CheckBox deadCodeCheck, antiDebugCheck, metadataRemovalCheck;
    private CheckBox classEncryptionCheck;
    private TextField licenseKeyField, serverUrlField;
    private Button encryptButton;

    // Page 2 components
    private RadioButton unlimitedRadio, limitedRadio;
    private Spinner<Integer> daysSpinner;
    private Label lastLicenseLabel;

    // Page 4 components
    private ComboBox<I18n.Language> languageCombo;
    private TextField mysqlHost, mysqlPort, mysqlUser, mysqlDatabase;
    private PasswordField mysqlPassword;
    private CheckBox loadBalancerCheck;
    private TextField backupHost;

    @Override
    public void start(Stage primaryStage) {
        instance = this; // Set static instance for global logging
        this.primaryStage = primaryStage;
        this.config = new ObfuscationConfig();
        this.database = new DatabaseManager();
        this.prefs = Preferences.userNodeForPackage(MainWindow.class);

        loadSettings();

        primaryStage.setTitle(Barron.NAME + "\\u2699" + Barron.VERSION);
        primaryStage.setMinWidth(900);
        primaryStage.setMinHeight(750);

        VBox root = new VBox(10);
        root.setPadding(new Insets(15));
        root.setStyle("-fx-background-color: #1a1a2e;");

        // Header
        HBox header = createHeader();

        // Tab Pane
        tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabPane.getTabs().addAll(
                createEncryptionTab(),
                createLicenseGenerationTab(),
                createManagementTab(),
                createSettingsTab());

        // Log area
        VBox logSection = createLogSection();

        root.getChildren().addAll(header, tabPane, logSection);
        VBox.setVgrow(tabPane, Priority.ALWAYS);

        Scene scene = new Scene(root, 950, 800);
        primaryStage.setScene(scene);
        primaryStage.show();

        log("Barron License Manager başlatıldı");
        connectDatabase();

        // Start server with configured ports
        int port = Integer.parseInt(prefs.get("server.port", "8000"));
        int webPort = Integer.parseInt(prefs.get("server.web_port", "8080"));

        config.setServerPort(port);
        config.setWebPort(webPort);

        // SSL Configuration
        boolean sslEnabled = prefs.getBoolean("ssl.enabled", false);
        String sslCertPath = prefs.get("ssl.cert_path", "");
        String sslKeyPath = prefs.get("ssl.key_path", "");

        // Server Domain
        String serverDomain = prefs.get("license.domain", "");
        dev.barron.server.LicenseServer.setServerDomain(serverDomain);

        dev.barron.server.LicenseServer.start(database, port, webPort, sslEnabled, sslCertPath, sslKeyPath);
        log("Servisler Başlatıldı - API: " + port + ", Web: " + webPort + (sslEnabled ? " (HTTPS)" : " (HTTP)"));
    }

    private HBox createHeader() {
        Label title = new Label("🛡️ BARRON LICENSE MANAGER");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 22));
        title.setTextFill(Color.web("#e94560"));

        Label version = new Label("v" + Barron.VERSION);
        version.setFont(Font.font("Segoe UI", 12));
        version.setTextFill(Color.web("#666666"));

        HBox header = new HBox(10, title, version);
        header.setAlignment(Pos.CENTER_LEFT);
        return header;
    }

    // ==================== PAGE 1: ENCRYPTION ====================

    private Tab createEncryptionTab() {
        Tab tab = new Tab(I18n.get("page.encrypt"));
        tab.setGraphic(createTabIcon("🔐"));

        VBox content = new VBox(15);
        content.setPadding(new Insets(20));
        content.setStyle("-fx-background-color: #16213e;");

        // Mode toggle
        Label modeLabel = new Label(I18n.get("encrypt.mode.normal") + " / " + I18n.get("encrypt.mode.server"));
        modeLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        modeLabel.setTextFill(Color.web("#8892b0"));

        ToggleGroup modeGroup = new ToggleGroup();

        normalModeBtn = new ToggleButton("⚡ " + I18n.get("encrypt.mode.normal"));
        normalModeBtn.setToggleGroup(modeGroup);
        normalModeBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");

        serverModeBtn = new ToggleButton("🔐 " + I18n.get("encrypt.mode.server"));
        serverModeBtn.setToggleGroup(modeGroup);
        serverModeBtn.setSelected(true);
        serverModeBtn.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white;");

        modeGroup.selectedToggleProperty().addListener((obs, oldVal, newVal) -> {
            serverModeEnabled = (newVal == serverModeBtn);
            updateModeStyles();
        });

        HBox modeBox = new HBox(10, normalModeBtn, serverModeBtn);
        modeBox.setAlignment(Pos.CENTER_LEFT);

        VBox modeSection = new VBox(5, modeLabel, modeBox);

        // Drop zone
        VBox dropZone = createDropZone();

        // Settings
        VBox settingsSection = createEncryptionSettings();

        // Encrypt button
        encryptButton = new Button(I18n.get("encrypt.button"));
        encryptButton.setFont(Font.font("Segoe UI", FontWeight.BOLD, 16));
        encryptButton.setStyle(
                "-fx-background-color: linear-gradient(to right, #e94560, #c73659); -fx-text-fill: white; -fx-padding: 15 40; -fx-background-radius: 25;");
        encryptButton.setDisable(true);
        encryptButton.setOnAction(e -> startEncryption());

        HBox buttonBox = new HBox(encryptButton);
        buttonBox.setAlignment(Pos.CENTER);

        content.getChildren().addAll(modeSection, dropZone, settingsSection, buttonBox);

        ScrollPane scrollPane = new ScrollPane(content);
        scrollPane.setFitToWidth(true);
        scrollPane.setStyle("-fx-background-color: transparent; -fx-background: transparent;");

        tab.setContent(scrollPane);
        return tab;
    }

    private void updateModeStyles() {
        if (serverModeEnabled) {
            serverModeBtn.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white;");
            normalModeBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        } else {
            normalModeBtn.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white;");
            serverModeBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        }
    }

    private VBox createDropZone() {
        dropLabel = new Label("📁 JAR DOSYASINI BURAYA SÜRÜKLE\nveya tıkla");
        dropLabel.setFont(Font.font("Segoe UI", FontWeight.MEDIUM, 16));
        dropLabel.setTextFill(Color.web("#8892b0"));
        dropLabel.setAlignment(Pos.CENTER);

        VBox zone = new VBox(dropLabel);
        zone.setAlignment(Pos.CENTER);
        zone.setPrefHeight(100);
        zone.setStyle(
                "-fx-background-color: #0a1628; -fx-border-color: #e94560; -fx-border-width: 2; -fx-border-style: dashed; -fx-border-radius: 10; -fx-background-radius: 10;");

        zone.setOnDragOver(event -> {
            if (event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        zone.setOnDragDropped(event -> {
            Dragboard db = event.getDragboard();
            if (db.hasFiles()) {
                File file = db.getFiles().get(0);
                if (file.getName().endsWith(".jar")) {
                    selectFile(file);
                    event.setDropCompleted(true);
                }
            }
            event.consume();
        });

        zone.setOnMouseClicked(event -> {
            FileChooser fc = new FileChooser();
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JAR Files", "*.jar"));
            File file = fc.showOpenDialog(primaryStage);
            if (file != null)
                selectFile(file);
        });

        return zone;
    }

    private void selectFile(File file) {
        this.selectedJar = file;
        dropLabel.setText(file.getName());
        dropLabel.setTextFill(Color.web("#00ff88"));
        encryptButton.setDisable(false);
        log("Dosya seçildi: " + file.getName());
    }

    private VBox createEncryptionSettings() {
        Label title = new Label("⚙️ " + I18n.get("encrypt.settings"));
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        stringEncryptionCheck = createCheckBox(I18n.get("encrypt.string"), true);
        identifierRenamingCheck = createCheckBox(I18n.get("encrypt.rename"), true);
        controlFlowCheck = createCheckBox(I18n.get("encrypt.controlflow"), true);
        deadCodeCheck = createCheckBox(I18n.get("encrypt.deadcode"), true);
        antiDebugCheck = createCheckBox(I18n.get("encrypt.antidebug"), true);
        metadataRemovalCheck = createCheckBox("Metadata Temizleme", true);
        classEncryptionCheck = createCheckBox("Class Encryption (Custom Loader)", true);

        GridPane grid = new GridPane();
        grid.setHgap(30);
        grid.setVgap(8);
        grid.add(stringEncryptionCheck, 0, 0);
        grid.add(identifierRenamingCheck, 1, 0);
        grid.add(controlFlowCheck, 0, 1);
        grid.add(deadCodeCheck, 1, 1);
        grid.add(antiDebugCheck, 0, 2);
        grid.add(metadataRemovalCheck, 1, 2);
        grid.add(classEncryptionCheck, 0, 3);

        VBox section = new VBox(10, title, grid);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private CheckBox createCheckBox(String text, boolean selected) {
        CheckBox cb = new CheckBox(text);
        cb.setSelected(selected);
        cb.setTextFill(Color.web("#8892b0"));
        return cb;
    }

    private void startEncryption() {
        if (selectedJar == null)
            return;

        log("═══════════════════════════════════════");
        log("Şifreleme başlıyor: " + selectedJar.getName());
        log("Mod: " + (serverModeEnabled ? "Sunucu Taraflı" : "Normal"));

        encryptButton.setDisable(true);

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                // Create output directory
                Path outputDir = Path.of(System.getProperty("user.dir"), "sifrelenmiş-pluginler");
                Files.createDirectories(outputDir);

                String outputName = selectedJar.getName().replace(".jar", "-protected.jar");
                Path outputPath = outputDir.resolve(outputName);

                // Configure
                config.setStringEncryption(stringEncryptionCheck.isSelected());
                config.setIdentifierRenaming(identifierRenamingCheck.isSelected());
                config.setControlFlowObfuscation(controlFlowCheck.isSelected());
                config.setDeadCodeInjection(deadCodeCheck.isSelected());
                config.setAntiDebug(antiDebugCheck.isSelected());
                config.setMetadataRemoval(metadataRemovalCheck.isSelected());
                config.setClassEncryption(classEncryptionCheck.isSelected());

                // License verification only in SERVER mode
                config.setLicenseVerification(serverModeEnabled);

                // Set license server domain (for Cloudflare protection)
                String domain = "localhost";
                if (licenseDomainField != null && !licenseDomainField.getText().trim().isEmpty()) {
                    domain = licenseDomainField.getText().trim()
                            .replace("http://", "")
                            .replace("https://", "")
                            .replaceAll(":\\d+$", ""); // Portu temizle (örn: :8443) çünkü aşağıda port ayrıca ekleniyor
                    config.setLicenseServerDomain(domain);
                }

                // Construct and set the full License Server URL automatically
                // Format: protocol://domain:port/api/verify
                String protocol = (sslEnabledCheck != null && sslEnabledCheck.isSelected()) ? "https" : "http";
                String port = (serverPortField != null && !serverPortField.getText().isEmpty())
                        ? serverPortField.getText().trim()
                        : "8000";

                String fullUrl = String.format("%s://%s:%s/api/verify", protocol, domain, port);
                config.setLicenseServerUrl(fullUrl);

                // Log the generated URL for debugging
                Platform.runLater(() -> log("Lisans URL ayarlandı: " + fullUrl));

                // Load Balancer Config
                if (loadBalancerEnabledCheck.isSelected() && !backupHostField.getText().isEmpty()) {
                    config.setBackupServerUrl(backupHostField.getText().trim());
                } else {
                    config.setBackupServerUrl(""); // Only meaningful if LB enabled
                }

                // Security (Dynamic Secret)
                if (secretKeyField != null) {
                    config.setTokenSecret(secretKeyField.getText());
                } else {
                    // Fallback to prefs if field is somehow null (e.g. tab not created yet)
                    config.setTokenSecret(prefs.get("security.token_secret", "BARRON-SECURE-2024-V1"));
                }

                // Obfuscate
                ObfuscationEngine engine = new ObfuscationEngine(config);
                engine.setLogCallback(MainWindow.this::log);
                engine.obfuscate(selectedJar.toPath(), outputPath);

                // Register in database
                if (serverModeEnabled) {
                    String hash = calculateFileHash(outputPath);
                    database.addPlugin(
                            selectedJar.getName().replace(".jar", ""),
                            outputName,
                            "1.0",
                            hash,
                            "SERVER");
                }

                return null;
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    encryptButton.setDisable(false);
                    log("\\u2705 Şifreleme tamamlandı!");
                    refreshPluginList();

                    Alert alert = new Alert(Alert.AlertType.INFORMATION);
                    alert.setTitle("Başarılı");
                    alert.setHeaderText("Plugin şifrelendi!");
                    alert.setContentText("Konum: sifrelenmiş-pluginler/");
                    alert.showAndWait();
                });
            }

            @Override
            protected void failed() {
                Platform.runLater(() -> {
                    encryptButton.setDisable(false);
                    log("\\u274C HATA: " + getException().getMessage());
                });
            }
        };

        new Thread(task).start();
    }

    private String calculateFileHash(Path path) throws Exception {
        byte[] bytes = Files.readAllBytes(path);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ==================== PAGE 2: LICENSE GENERATION ====================

    private Tab createLicenseGenerationTab() {
        Tab tab = new Tab(I18n.get("page.licenses"));
        tab.setGraphic(createTabIcon("🎫"));

        VBox content = new VBox(15);
        content.setPadding(new Insets(20));
        content.setStyle("-fx-background-color: #16213e;");

        // Plugin list
        Label listTitle = new Label("📋 " + I18n.get("license.plugins"));
        listTitle.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        listTitle.setTextFill(Color.web("#e94560"));

        pluginList = new ListView<>();
        pluginList.setPrefHeight(200);
        pluginList.setStyle("-fx-background-color: #000000; -fx-control-inner-background: #000000;");
        pluginList.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(DatabaseManager.PluginInfo item, boolean empty) {
                super.updateItem(item, empty);

                // Style based on selection state
                if (isSelected() && item != null) {
                    // Selected: green border with dark green background
                    setStyle(
                            "-fx-background-color: #003322; -fx-border-color: #00ff88; -fx-border-width: 2; -fx-border-radius: 3;");
                    setTextFill(Color.web("#00ff88"));
                } else {
                    // Not selected: plain black background
                    setStyle("-fx-background-color: #000000;");
                    setTextFill(Color.web("#00ff88"));
                }

                if (empty || item == null) {
                    setText(null);
                    setStyle("-fx-background-color: #000000;");
                } else {
                    setText(String.format("%s [%d lisans]", item.filename(), item.licenseCount()));
                }
            }
        });

        pluginList.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) {
                createLicenseForSelected();
            }
        });

        // Plugin action buttons
        Button deletePluginBtn = new Button("🗑️ Plugin Sil");
        deletePluginBtn.setStyle("-fx-background-color: #dd3333; -fx-text-fill: white;");
        deletePluginBtn.setOnAction(e -> deleteSelectedPlugin());

        Button refreshPluginsBtn = new Button("🔄 Yenile");
        refreshPluginsBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        refreshPluginsBtn.setOnAction(e -> refreshPluginList());

        Label hint = new Label("💡 " + I18n.get("license.doubleclick"));
        hint.setTextFill(Color.web("#666666"));

        HBox pluginButtons = new HBox(10, deletePluginBtn, refreshPluginsBtn, hint);
        pluginButtons.setAlignment(Pos.CENTER_LEFT);

        // Duration settings
        Label durationTitle = new Label("⏱️ " + I18n.get("license.duration"));
        durationTitle.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        durationTitle.setTextFill(Color.web("#8892b0"));

        ToggleGroup durationGroup = new ToggleGroup();
        unlimitedRadio = new RadioButton(I18n.get("license.unlimited"));
        unlimitedRadio.setToggleGroup(durationGroup);
        unlimitedRadio.setTextFill(Color.web("#8892b0"));

        limitedRadio = new RadioButton(I18n.get("license.limited"));
        limitedRadio.setToggleGroup(durationGroup);
        limitedRadio.setSelected(true);
        limitedRadio.setTextFill(Color.web("#8892b0"));

        daysSpinner = new Spinner<>(1, 365, 30);
        daysSpinner.setEditable(true);
        daysSpinner.setPrefWidth(80);

        Label daysLabel = new Label(I18n.get("license.days"));
        daysLabel.setTextFill(Color.web("#8892b0"));

        HBox durationBox = new HBox(15, unlimitedRadio, limitedRadio, daysSpinner, daysLabel);
        durationBox.setAlignment(Pos.CENTER_LEFT);

        // Last created license
        lastLicenseLabel = new Label("");
        lastLicenseLabel.setFont(Font.font("Consolas", FontWeight.BOLD, 16));
        lastLicenseLabel.setTextFill(Color.web("#00ff88"));

        Button copyBtn = new Button("📋 " + I18n.get("license.copy"));
        copyBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        copyBtn.setOnAction(e -> copyToClipboard(lastLicenseLabel.getText()));

        HBox lastBox = new HBox(15, lastLicenseLabel, copyBtn);
        lastBox.setAlignment(Pos.CENTER_LEFT);

        content.getChildren().addAll(listTitle, pluginList, pluginButtons, durationTitle, durationBox, lastBox);

        ScrollPane scrollPane = new ScrollPane(content);
        scrollPane.setFitToWidth(true);
        scrollPane.setStyle("-fx-background-color: transparent; -fx-background: transparent;");

        tab.setContent(scrollPane);
        return tab;
    }

    private void createLicenseForSelected() {
        DatabaseManager.PluginInfo selected = pluginList.getSelectionModel().getSelectedItem();
        if (selected == null)
            return;

        try {
            Integer days = unlimitedRadio.isSelected() ? null : daysSpinner.getValue();
            String licenseKey = database.createLicense(selected.id(), days);

            lastLicenseLabel.setText(licenseKey);
            log("\\u2705 Lisans oluşturuldu: " + licenseKey);

            refreshPluginList();
        } catch (Exception e) {
            log("\\u274C Lisans oluşturma hatası: " + e.getMessage());
        }
    }

    private void refreshPluginList() {
        try {
            pluginList.getItems().clear();
            pluginList.getItems().addAll(database.getAllPlugins());
        } catch (Exception e) {
            log("Plugin listesi yüklenemedi: " + e.getMessage());
        }
    }

    private void deleteSelectedPlugin() {
        DatabaseManager.PluginInfo selected = pluginList.getSelectionModel().getSelectedItem();
        if (selected == null) {
            log("⚠️ Lütfen silmek için bir plugin seçin");
            return;
        }

        // Confirmation dialog
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Plugin Sil");
        confirm.setHeaderText("Plugin silinecek: " + selected.filename());
        confirm.setContentText("Bu plugin ve tüm lisansları silinecek. Emin misiniz?");

        confirm.showAndWait().ifPresent(response -> {
            if (response == ButtonType.OK) {
                try {
                    database.deletePlugin(selected.id());
                    log("\\u2705 Plugin silindi: " + selected.filename());
                    refreshPluginList();
                } catch (Exception e) {
                    log("\\u274C Plugin silinemedi: " + e.getMessage());
                }
            }
        });
    }

    // ==================== PAGE 3: MANAGEMENT ====================

    private Tab createManagementTab() {
        Tab tab = new Tab(I18n.get("page.manage"));
        tab.setGraphic(createTabIcon("📊"));

        VBox content = new VBox(15);
        content.setPadding(new Insets(20));
        content.setStyle("-fx-background-color: #16213e;");

        // Search
        TextField searchField = new TextField();
        searchField.setPromptText(I18n.get("manage.search"));
        searchField.setStyle("-fx-background-color: #0a1628; -fx-text-fill: white;");

        // Table
        licenseTable = new TableView<>();
        licenseTable.setStyle("-fx-background-color: #0a1628;");

        TableColumn<DatabaseManager.LicenseInfo, String> keyCol = new TableColumn<>(I18n.get("manage.key"));
        keyCol.setCellValueFactory(
                data -> new javafx.beans.property.SimpleStringProperty(data.getValue().licenseKey()));
        keyCol.setPrefWidth(150);

        TableColumn<DatabaseManager.LicenseInfo, String> userCol = new TableColumn<>(I18n.get("manage.user"));
        userCol.setCellValueFactory(data -> new javafx.beans.property.SimpleStringProperty(
                data.getValue().email() != null ? data.getValue().email() : I18n.get("manage.notactivated")));
        userCol.setPrefWidth(150);

        TableColumn<DatabaseManager.LicenseInfo, String> ipCol = new TableColumn<>(I18n.get("manage.ips"));
        ipCol.setCellValueFactory(data -> new javafx.beans.property.SimpleStringProperty(
                data.getValue().ipList() != null ? data.getValue().ipList() : "-"));
        ipCol.setPrefWidth(150);

        TableColumn<DatabaseManager.LicenseInfo, String> expiresCol = new TableColumn<>(I18n.get("manage.expires"));
        expiresCol.setCellValueFactory(data -> {
            var exp = data.getValue().expiresAt();
            if (exp == null)
                return new javafx.beans.property.SimpleStringProperty("∞");
            long days = (exp.getTime() - System.currentTimeMillis()) / (24 * 60 * 60 * 1000);
            return new javafx.beans.property.SimpleStringProperty(days + "\\uD83C\\uDF10" + I18n.get("license.days"));
        });
        expiresCol.setPrefWidth(80);

        TableColumn<DatabaseManager.LicenseInfo, String> statusCol = new TableColumn<>(I18n.get("manage.status"));
        statusCol.setCellValueFactory(data -> new javafx.beans.property.SimpleStringProperty(
                data.getValue().isOnline() ? "🟢" : "⚫"));
        statusCol.setPrefWidth(60);

        licenseTable.getColumns().addAll(keyCol, userCol, ipCol, expiresCol, statusCol);

        // Buttons
        Button refreshBtn = new Button("🔄 " + I18n.get("manage.refresh"));
        refreshBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        refreshBtn.setOnAction(e -> refreshLicenseTable());

        Button deleteBtn = new Button("🗑️ " + I18n.get("manage.delete"));
        deleteBtn.setStyle("-fx-background-color: #dd3333; -fx-text-fill: white;");
        deleteBtn.setOnAction(e -> deleteSelectedLicense());

        HBox buttonBox = new HBox(15, refreshBtn, deleteBtn);
        buttonBox.setPadding(new Insets(10, 0, 0, 0));

        BorderPane layout = new BorderPane();
        layout.setPadding(new Insets(20));
        layout.setStyle("-fx-background-color: #16213e;");

        VBox topBox = new VBox(10, searchField);
        topBox.setPadding(new Insets(0, 0, 10, 0));

        layout.setTop(topBox);
        layout.setCenter(licenseTable);
        layout.setBottom(buttonBox);

        tab.setContent(layout);
        return tab;
    }

    private void refreshLicenseTable() {
        try {
            licenseTable.getItems().clear();
            licenseTable.getItems().addAll(database.getAllLicenses());
            log("Lisans listesi yenilendi");
        } catch (Exception e) {
            log("\\u274C " + e.getMessage());
        }
    }

    private void deleteSelectedLicense() {
        var selected = licenseTable.getSelectionModel().getSelectedItem();
        if (selected != null) {
            try {
                database.deleteLicense(selected.id());
                refreshLicenseTable();
                log("Lisans silindi: " + selected.licenseKey());
            } catch (Exception e) {
                log("\\u274C " + e.getMessage());
            }
        }
    }

    // ==================== PAGE 4: SETTINGS ====================

    private Tab createSettingsTab() {
        Tab tab = new Tab(I18n.get("page.settings"));
        tab.setGraphic(createTabIcon("⚙️"));

        VBox content = new VBox(20);
        content.setPadding(new Insets(20));
        content.setStyle("-fx-background-color: #16213e;");

        // Language
        VBox langSection = createLanguageSection();

        // Network
        VBox networkSection = createNetworkSection();

        // Security (Secret Key)
        VBox securitySection = createSecuritySection();

        // MySQL
        VBox mysqlSection = createMySQLSection();

        // Load Balancer
        // Load Balancer (License Server)
        VBox lbSection = createLoadBalancerSection();

        // Database Failover (MySQL)
        VBox dbFailoverSection = createDatabaseFailoverSection();

        // SMTP
        VBox smtpSection = createSmtpSection();

        // Payment
        VBox paymentSection = createPaymentSection();

        // Save button
        Button saveBtn = new Button("💾 " + I18n.get("settings.save"));
        saveBtn.setStyle(
                "-fx-background-color: #00aa55; -fx-text-fill: white; -fx-font-weight: bold; -fx-padding: 15 40;");
        saveBtn.setOnAction(e -> saveSettings());

        HBox saveBox = new HBox(saveBtn);
        saveBox.setAlignment(Pos.CENTER);

        content.getChildren().addAll(langSection, networkSection, securitySection, mysqlSection, lbSection,
                dbFailoverSection, smtpSection,
                paymentSection,
                saveBox);

        ScrollPane scrollPane = new ScrollPane(content);
        scrollPane.setFitToWidth(true);
        scrollPane.setStyle("-fx-background-color: transparent; -fx-background: transparent;");

        tab.setContent(scrollPane);
        return tab;
    }

    private TextField backupHostField;
    private CheckBox loadBalancerEnabledCheck;

    private VBox createLoadBalancerSection() {
        Label title = new Label("⚖️ " + "LOAD BALANCER & FAILOVER");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        loadBalancerEnabledCheck = new CheckBox("Load Balancer Aktif");
        loadBalancerEnabledCheck.setSelected(prefs.getBoolean("lb.enabled", false));
        loadBalancerEnabledCheck.setTextFill(Color.WHITE);

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        backupHostField = new TextField(prefs.get("lb.backup_ip", ""));
        backupHostField.setPromptText("backup.example.com veya IP");
        styleTextField(backupHostField);

        grid.addRow(0, createLabel("Yedek Sunucu IP/Domain:"), backupHostField);

        Label infoLabel = new Label(
                "Ana sunucu çökmesi durumunda lisans kontrolü otomatik olarak\nbu adrese yönlendirilir.");
        infoLabel.setTextFill(Color.web("#888888"));
        infoLabel.setFont(Font.font("Segoe UI", 10));

        Label warningLabel = new Label("DİKKAT: Bu özellik şifreleme işleminden ÖNCE aktif edilmelidir!");
        warningLabel.setTextFill(Color.web("#e94560")); // Red color
        warningLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 10));

        VBox section = new VBox(15, title, loadBalancerEnabledCheck, grid, infoLabel, warningLabel);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private TextField serverPortField;
    private Hyperlink serverLink;
    private TextField webPortField;
    private Hyperlink webLink;
    private TextField licenseDomainField;
    private CheckBox sslEnabledCheck;
    private TextField sslCertField;
    private TextField sslKeyField;

    private VBox createNetworkSection() {
        Label title = new Label("🌐 " + "NETWORK & SERVER");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        // API Port
        String currentPort = prefs.get("server.port", "8000");
        serverPortField = new TextField(currentPort);
        styleTextField(serverPortField);

        serverLink = new Hyperlink("(http://localhost:" + currentPort + ")");
        serverLink.setTextFill(Color.web("#00aa55"));
        serverLink.setOnAction(e -> getHostServices().showDocument("http://localhost:" + currentPort + "/api/verify"));

        grid.addRow(0, createLabel("API Server Port:"), serverPortField, serverLink);

        // Web Panel Port
        String currentWebPort = prefs.get("server.web_port", "8080");
        webPortField = new TextField(currentWebPort);
        styleTextField(webPortField);

        webLink = new Hyperlink("(http://localhost:" + currentWebPort + ")");
        webLink.setTextFill(Color.web("#00aa55"));
        webLink.setOnAction(e -> getHostServices().showDocument("http://localhost:" + currentWebPort));

        grid.addRow(1, createLabel("Web Panel Port:"), webPortField, webLink);

        // License Server Domain (for Cloudflare)
        String currentDomain = prefs.get("license.domain", "");
        licenseDomainField = new TextField(currentDomain);
        licenseDomainField.setPromptText("api.example.com (http/s yazmayın)");
        styleTextField(licenseDomainField);

        Label domainInfo = new Label("Sadece Domain veya IP (Örn: 192.168.1.1). Protokol (http/s) otomatik eklenir.");
        domainInfo.setTextFill(Color.web("#888888"));
        domainInfo.setFont(Font.font("Segoe UI", 10));

        grid.addRow(2, createLabel("License Domain:"), licenseDomainField, domainInfo);

        Label infoLabel = new Label("Varsayılan: API 8000, Web 8080. Portları firewall'dan açmayı unutmayın.");
        infoLabel.setTextFill(Color.web("#666666"));

        // SSL Settings Section
        Label sslTitle = new Label("🔒 SSL / HTTPS");
        sslTitle.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        sslTitle.setTextFill(Color.web("#00aa55"));
        sslTitle.setPadding(new Insets(10, 0, 0, 0));

        sslEnabledCheck = new CheckBox("SSL Aktif (HTTPS)");
        sslEnabledCheck.setTextFill(Color.WHITE);
        sslEnabledCheck.setSelected(prefs.getBoolean("ssl.enabled", false));

        // Certificate Path
        Label certLabel = createLabel("Origin Certificate:");
        sslCertField = new TextField(prefs.get("ssl.cert_path", ""));
        sslCertField.setPromptText("cert.pem dosya yolu");
        styleTextField(sslCertField);
        sslCertField.setPrefWidth(250);
        Button certBrowseBtn = new Button("...");
        certBrowseBtn.setOnAction(e -> {
            javafx.stage.FileChooser fc = new javafx.stage.FileChooser();
            fc.setTitle("Sertifika Dosyası Seç (.pem)");
            fc.getExtensionFilters().add(new javafx.stage.FileChooser.ExtensionFilter("PEM Files", "*.pem", "*.crt"));
            java.io.File f = fc.showOpenDialog(null);
            if (f != null)
                sslCertField.setText(f.getAbsolutePath());
        });
        HBox certBox = new HBox(5, sslCertField, certBrowseBtn);

        // Key Path
        Label keyLabel = createLabel("Private Key:");
        sslKeyField = new TextField(prefs.get("ssl.key_path", ""));
        sslKeyField.setPromptText("key.pem dosya yolu");
        styleTextField(sslKeyField);
        sslKeyField.setPrefWidth(250);
        Button keyBrowseBtn = new Button("...");
        keyBrowseBtn.setOnAction(e -> {
            javafx.stage.FileChooser fc = new javafx.stage.FileChooser();
            fc.setTitle("Private Key Dosyası Seç (.pem)");
            fc.getExtensionFilters().add(new javafx.stage.FileChooser.ExtensionFilter("PEM Files", "*.pem", "*.key"));
            java.io.File f = fc.showOpenDialog(null);
            if (f != null)
                sslKeyField.setText(f.getAbsolutePath());
        });
        HBox keyBox = new HBox(5, sslKeyField, keyBrowseBtn);

        GridPane sslGrid = new GridPane();
        sslGrid.setHgap(10);
        sslGrid.setVgap(5);
        sslGrid.addRow(0, certLabel, certBox);
        sslGrid.addRow(1, keyLabel, keyBox);

        Label sslInfoLabel = new Label("Cloudflare Origin Certificate kullanarak HTTPS aktif edin.");
        sslInfoLabel.setTextFill(Color.web("#888888"));
        sslInfoLabel.setFont(Font.font("Segoe UI", 10));

        VBox section = new VBox(10, title, grid, infoLabel, sslTitle, sslEnabledCheck, sslGrid, sslInfoLabel);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private VBox createLanguageSection() {
        Label title = new Label("🌐 " + I18n.get("settings.language"));
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        languageCombo = new ComboBox<>();
        languageCombo.getItems().addAll(I18n.Language.values());
        languageCombo.setValue(I18n.getLanguage());
        languageCombo.setConverter(new javafx.util.StringConverter<>() {
            @Override
            public String toString(I18n.Language lang) {
                return lang != null ? lang.getDisplayName() : "";
            }

            @Override
            public I18n.Language fromString(String s) {
                return null;
            }
        });

        VBox section = new VBox(10, title, languageCombo);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private VBox createMySQLSection() {
        Label title = new Label("🗄️ " + I18n.get("settings.mysql"));
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        mysqlHost = new TextField(prefs.get("mysql.host", "localhost"));
        mysqlPort = new TextField(prefs.get("mysql.port", "3306"));
        mysqlUser = new TextField(prefs.get("mysql.user", "barron"));
        mysqlPassword = new PasswordField();
        mysqlDatabase = new TextField(prefs.get("mysql.database", "barron_licenses"));

        styleTextField(mysqlHost);
        styleTextField(mysqlPort);
        styleTextField(mysqlUser);
        styleTextField(mysqlPassword);
        styleTextField(mysqlDatabase);

        grid.addRow(0, createLabel("Host:"), mysqlHost, createLabel("Port:"), mysqlPort);
        grid.addRow(1, createLabel("User:"), mysqlUser, createLabel("Password:"), mysqlPassword);
        grid.addRow(2, createLabel("Database:"), mysqlDatabase);

        Button testBtn = new Button("🔗 " + I18n.get("settings.test"));
        testBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        testBtn.setOnAction(e -> testMySQLConnection());

        VBox section = new VBox(10, title, grid, testBtn);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private TextField failoverHost, failoverPort, failoverUser, failoverPass;
    private CheckBox failoverEnabledCheck;

    private VBox createDatabaseFailoverSection() {
        Label title = new Label("🔄 " + "FAILOVER / REMOTE BACKUP");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        failoverEnabledCheck = new CheckBox("Failover / Otomatik Yedekleme Aktif");
        failoverEnabledCheck.setTextFill(Color.web("#8892b0"));
        failoverEnabledCheck.setSelected(prefs.getBoolean("failover.enabled", false));

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        // Host
        failoverHost = new TextField(prefs.get("failover.host", ""));
        failoverHost.setPromptText("Yedek Sunucu IP");
        styleTextField(failoverHost);
        grid.addRow(0, createLabel("Host:"), failoverHost);

        // Port
        failoverPort = new TextField(prefs.get("failover.port", "3306"));
        styleTextField(failoverPort);
        failoverPort.setPrefWidth(80);
        grid.addRow(1, createLabel("Port:"), failoverPort);

        // User
        failoverUser = new TextField(prefs.get("failover.user", "root"));
        styleTextField(failoverUser);
        grid.addRow(2, createLabel("User:"), failoverUser);

        // Pass
        failoverPass = new PasswordField();
        failoverPass.setText(prefs.get("failover.pass", ""));
        styleTextField(failoverPass);
        grid.addRow(3, createLabel("Pass:"), failoverPass);

        // Enable/Disable fields
        toggleFailoverFields(failoverEnabledCheck.isSelected());
        failoverEnabledCheck.setOnAction(e -> toggleFailoverFields(failoverEnabledCheck.isSelected()));

        Button saveBtn = new Button("💾 " + I18n.get("settings.save"));
        saveBtn.setStyle("-fx-background-color: #00aa55; -fx-text-fill: white; -fx-font-weight: bold;");
        saveBtn.setOnAction(e -> saveSettings());

        VBox section = new VBox(15, title, failoverEnabledCheck, grid);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private void toggleFailoverFields(boolean enabled) {
        failoverHost.setDisable(!enabled);
        failoverPort.setDisable(!enabled);
        failoverUser.setDisable(!enabled);
        failoverPass.setDisable(!enabled);
    }

    private void styleTextField(TextField tf) {
        tf.setStyle("-fx-background-color: #16213e; -fx-text-fill: #00ff88; -fx-border-color: #333;");
    }

    private Label createLabel(String text) {
        Label label = new Label(text);
        label.setTextFill(Color.web("#8892b0"));
        label.setMinWidth(60);
        return label;
    }

    private void testMySQLConnection() {
        database.configure(
                mysqlHost.getText(),
                Integer.parseInt(mysqlPort.getText()),
                mysqlDatabase.getText(),
                mysqlUser.getText(),
                mysqlPassword.getText());

        if (database.testConnection()) {
            log("\\u2705 MySQL bağlantısı başarılı!");
            showInfo("MySQL bağlantısı başarılı!");
        } else {
            log("\\u274C MySQL bağlantısı başarısız!");
            showError("MySQL bağlantısı başarısız!");
        }
    }

    // Deprecated direct copy, now handled by failover replication
    private void copyToBackup() {
        // Implementation replaced by real-time failover
        showInfo("Otomatik yedekleme aktifse veriler anlık işlenir.");
    }

    private void saveSettings() {
        // Main DB
        prefs.put("mysql.host", mysqlHost.getText());
        prefs.put("mysql.port", mysqlPort.getText());
        prefs.put("mysql.user", mysqlUser.getText());
        prefs.put("mysql.database", mysqlDatabase.getText());

        // Language
        prefs.put("language", languageCombo.getValue().getCode());

        // Server
        prefs.put("server.port", serverPortField.getText());
        prefs.put("server.web_port", webPortField.getText());
        prefs.put("server.web_port", webPortField.getText());
        prefs.put("license.domain", licenseDomainField.getText());

        // Security
        prefs.put("security.token_secret", secretKeyField.getText());

        // SSL
        prefs.putBoolean("ssl.enabled", sslEnabledCheck.isSelected());
        prefs.put("ssl.cert_path", sslCertField.getText());
        prefs.put("ssl.key_path", sslKeyField.getText());

        // Failover
        prefs.putBoolean("failover.enabled", failoverEnabledCheck.isSelected());
        prefs.put("failover.host", failoverHost.getText());
        prefs.put("failover.port", failoverPort.getText());
        prefs.put("failover.user", failoverUser.getText());
        prefs.put("failover.pass", failoverPass.getText());

        // SMTP
        prefs.put("smtp.host", smtpHost.getText());
        prefs.put("smtp.port", smtpPort.getText());
        prefs.put("smtp.security", smtpSecurityType.getValue());
        prefs.put("smtp.user", smtpUser.getText());
        prefs.put("smtp.pass", smtpPass.getText());
        prefs.put("smtp.from", smtpFrom.getText());
        prefs.putBoolean("smtp.enabled", smtpEnabledCheck.isSelected());

        // Payment
        prefs.put("payment.provider", paymentProvider.getValue());
        prefs.put("payment.apiKey", paymentApiKey.getText());
        prefs.put("payment.apiSecret", paymentApiSecret.getText());
        prefs.put("payment.webhook", paymentWebhookSecret.getText());
        prefs.put("payment.merchant", paymentMerchantId.getText());
        prefs.putBoolean("payment.enabled", paymentEnabledSwitch.isSelected());
        prefs.putBoolean("payment.test", !paymentLiveModeSwitch.isSelected()); // Live = not test

        try {
            int port = Integer.parseInt(serverPortField.getText());
            int webPort = Integer.parseInt(webPortField.getText());

            config.setServerPort(port);
            config.setWebPort(webPort);
            config.setTokenSecret(secretKeyField.getText());

            // SSL
            boolean sslEnabled = sslEnabledCheck.isSelected();
            String sslCertPath = sslCertField.getText();
            String sslKeyPath = sslKeyField.getText();

            // Failover Config
            if (failoverEnabledCheck.isSelected()) {
                database.configureSecondary(
                        failoverHost.getText(),
                        Integer.parseInt(failoverPort.getText()),
                        failoverUser.getText(),
                        failoverPass.getText());
            } else {
                database.setFailoverEnabled(false);
            }

            // Sync Settings to DB (SMTP & Payment)
            if (database.isConnected()) {
                database.saveSmtpSettings(
                        smtpHost.getText(),
                        Integer.parseInt(smtpPort.getText()),
                        smtpSecurityType.getValue(),
                        smtpUser.getText(),
                        smtpPass.getText(),
                        smtpFrom.getText(),
                        smtpEnabledCheck.isSelected());
                database.savePaymentSettings(
                        paymentProvider.getValue(),
                        paymentApiKey.getText(),
                        paymentApiSecret.getText(),
                        paymentWebhookSecret.getText(),
                        paymentMerchantId.getText(),
                        paymentEnabledSwitch.isSelected(),
                        !paymentLiveModeSwitch.isSelected()); // test mode = NOT live mode
            }

            // Restart Server
            String rawDomain = licenseDomainField.getText().trim();
            String cleanDomain = rawDomain
                    .replace("http://", "")
                    .replace("https://", "")
                    .replaceAll(":\\d+$", "");

            // Save clean domain to prefs to avoid future issues
            prefs.put("license.domain", cleanDomain);

            dev.barron.server.LicenseServer.setServerDomain(cleanDomain);
            dev.barron.server.LicenseServer.start(database, port, webPort, sslEnabled, sslCertPath, sslKeyPath);

            // Update UI Links
            String protocol = sslEnabled ? "https" : "http";
            serverLink.setText("(" + protocol + "://localhost:" + port + ")");
            serverLink.setOnAction(
                    ev -> getHostServices().showDocument(protocol + "://localhost:" + port + "/api/verify"));

            webLink.setText("(" + protocol + "://localhost:" + webPort + ")");
            webLink.setOnAction(ev -> getHostServices().showDocument(protocol + "://localhost:" + webPort));

            log("Ayarlar kaydedildi ve sunucu yeniden başlatıldı.");
            showInfo("Ayarlar başarıyla kaydedildi!");

        } catch (NumberFormatException | SQLException e) {
            log("\\u274C Hata: " + e.getMessage());
            showError("Kaydetme hatası: " + e.getMessage());
        }

        I18n.setLanguage(languageCombo.getValue());
    }

    // ==================== NEW SECTIONS ====================

    private PasswordField secretKeyField;
    private TextField secretKeyVisibleField;
    private Button toggleSecretBtn;
    private boolean isSecretVisible = false;

    private VBox createSecuritySection() {
        Label title = new Label("🔒 " + "SECURITY & ENCRYPTION");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        // Secret Key Field
        String currentSecret = prefs.get("security.token_secret", "BARRON-SECURE-2024-V1");

        secretKeyField = new PasswordField();
        secretKeyField.setText(currentSecret);
        styleTextField(secretKeyField);
        secretKeyField.setPrefWidth(250);

        secretKeyVisibleField = new TextField();
        secretKeyVisibleField.setText(currentSecret);
        styleTextField(secretKeyVisibleField);
        secretKeyVisibleField.setPrefWidth(250);
        secretKeyVisibleField.setVisible(false);
        secretKeyVisibleField.setManaged(false);

        // Sync fields
        secretKeyField.textProperty().bindBidirectional(secretKeyVisibleField.textProperty());

        toggleSecretBtn = new Button("Göster");
        toggleSecretBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: white; -fx-font-size: 10px;");
        toggleSecretBtn.setOnAction(e -> {
            isSecretVisible = !isSecretVisible;
            if (isSecretVisible) {
                toggleSecretBtn.setText("Gizle");
                secretKeyVisibleField.setVisible(true);
                secretKeyVisibleField.setManaged(true);
                secretKeyField.setVisible(false);
                secretKeyField.setManaged(false);
            } else {
                toggleSecretBtn.setText("Göster");
                secretKeyVisibleField.setVisible(false);
                secretKeyVisibleField.setManaged(false);
                secretKeyField.setVisible(true);
                secretKeyField.setManaged(true);
            }
        });

        HBox secretBox = new HBox(5, secretKeyField, secretKeyVisibleField, toggleSecretBtn);
        secretBox.setAlignment(Pos.CENTER_LEFT);

        grid.addRow(0, createLabel("License Secret Master Key:"), secretBox);

        // Restore Button
        Button restoreBtn = new Button("Son Kayıtlıyı Geri Yükle");
        restoreBtn.setStyle("-fx-background-color: #2c3e50; -fx-text-fill: #ecf0f1; -fx-font-size: 11px;");
        restoreBtn.setOnAction(e -> {
            String saved = prefs.get("security.token_secret", "BARRON-SECURE-2024-V1");
            secretKeyField.setText(saved);
            showInfo("Son kaydedilen şifre geri yüklendi.");
        });

        grid.add(restoreBtn, 1, 1);

        // Red Warning
        Label warningLabel = new Label(
                "DİKKAT: Bu anahtarı değiştirmek, daha önce oluşturulmuş\ntüm lisansların geçersiz olmasına neden olur!");
        warningLabel.setTextFill(Color.RED);
        warningLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        warningLabel.setStyle("-fx-border-color: red; -fx-border-width: 1; -fx-padding: 5;");

        VBox section = new VBox(15, title, grid, warningLabel);
        section.setPadding(new Insets(10));
        section.setStyle(
                "-fx-background-color: #0a1628; -fx-background-radius: 10; border-color: #e94560; border-width: 1;");
        return section;
    }

    private TextField smtpHost, smtpPort, smtpUser, smtpPass, smtpFrom;
    private CheckBox smtpEnabledCheck;
    private ComboBox<String> smtpSecurityType;

    private VBox createSmtpSection() {
        Label title = new Label("📧 SMTP / EMAIL");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        smtpEnabledCheck = new CheckBox("Email Servisi Aktif");
        smtpEnabledCheck.setTextFill(Color.web("#8892b0"));
        smtpEnabledCheck.setSelected(prefs.getBoolean("smtp.enabled", false));

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        // SMTP Sunucusu (Host)
        smtpHost = new TextField(prefs.get("smtp.host", ""));
        smtpHost.setPromptText("smtp.example.com");
        styleTextField(smtpHost);
        grid.addRow(0, createLabel("SMTP Sunucusu:"), smtpHost);

        // SMTP Portu
        smtpPort = new TextField(prefs.get("smtp.port", ""));
        smtpPort.setPromptText("465 veya 587");
        styleTextField(smtpPort);
        grid.addRow(1, createLabel("SMTP Portu:"), smtpPort);

        // SMTP Güvenliği (Security Type)
        smtpSecurityType = new ComboBox<>();
        smtpSecurityType.getItems().addAll("SSL", "TLS", "STARTTLS", "Yok");
        smtpSecurityType.setValue(prefs.get("smtp.security", "SSL"));
        smtpSecurityType.setStyle("-fx-background-color: #16213e; -fx-mark-color: white;");
        smtpSecurityType.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(item);
                setStyle("-fx-background-color: #16213e; -fx-text-fill: white;");
            }
        });
        smtpSecurityType.setButtonCell(new ListCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(item);
                setStyle("-fx-text-fill: white; -fx-background-color: transparent;");
            }
        });
        grid.addRow(2, createLabel("SMTP Güvenliği:"), smtpSecurityType);

        // SMTP Gönderen E-posta Adresi (From)
        smtpFrom = new TextField(prefs.get("smtp.from", ""));
        smtpFrom.setPromptText("noreply@example.com");
        styleTextField(smtpFrom);
        grid.addRow(3, createLabel("Gönderen E-posta:"), smtpFrom);

        // SMTP Kullanıcı Adı (User)
        smtpUser = new TextField(prefs.get("smtp.user", ""));
        smtpUser.setPromptText("user@example.com");
        styleTextField(smtpUser);
        grid.addRow(4, createLabel("Kullanıcı Adı:"), smtpUser);

        // SMTP Parolası (Pass)
        smtpPass = new PasswordField();
        smtpPass.setText(prefs.get("smtp.pass", ""));
        smtpPass.setPromptText("••••••••");
        styleTextField(smtpPass);
        grid.addRow(5, createLabel("Parola:"), smtpPass);

        // Test Button
        Button testSmtpBtn = new Button("🔗 Bağlantıyı Test Et");
        testSmtpBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        testSmtpBtn.setOnAction(e -> testSmtpConnection());

        VBox section = new VBox(15, title, smtpEnabledCheck, grid, testSmtpBtn);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private void testSmtpConnection() {
        String host = smtpHost.getText();
        String portStr = smtpPort.getText();
        String user = smtpUser.getText();
        String pass = smtpPass.getText();
        String security = smtpSecurityType.getValue();

        if (host.isEmpty() || portStr.isEmpty()) {
            showError("SMTP Sunucusu ve Port boş olamaz!");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            showError("Geçersiz port numarası!");
            return;
        }

        log("📧 SMTP bağlantısı test ediliyor: " + host + ":" + port + " (" + security + ")");

        // Run in background thread to avoid blocking UI
        new Thread(() -> {
            try {
                java.util.Properties props = new java.util.Properties();
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.host", host);
                props.put("mail.smtp.port", String.valueOf(port));
                props.put("mail.smtp.connectiontimeout", "10000");
                props.put("mail.smtp.timeout", "10000");

                // Configure based on security type
                switch (security) {
                    case "SSL" -> {
                        props.put("mail.smtp.ssl.enable", "true");
                        props.put("mail.smtp.ssl.trust", host);
                        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
                        props.put("mail.smtp.socketFactory.port", String.valueOf(port));
                    }
                    case "TLS", "STARTTLS" -> {
                        props.put("mail.smtp.starttls.enable", "true");
                        props.put("mail.smtp.starttls.required", "true");
                        props.put("mail.smtp.ssl.trust", host);
                    }
                    // "Yok" - no security
                }

                javax.mail.Session session = javax.mail.Session.getInstance(props, new javax.mail.Authenticator() {
                    protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                        return new javax.mail.PasswordAuthentication(user, pass);
                    }
                });

                // Try to connect
                String protocol = "SSL".equals(security) ? "smtps" : "smtp";
                javax.mail.Transport transport = session.getTransport(protocol);
                transport.connect(host, port, user, pass);
                transport.close();

                Platform.runLater(() -> {
                    log("\\u2705 SMTP bağlantısı başarılı!");
                    showInfo("SMTP bağlantısı başarılı!");
                });
            } catch (javax.mail.AuthenticationFailedException e) {
                Platform.runLater(() -> {
                    log("\\u274C SMTP kimlik doğrulama hatası: " + e.getMessage());
                    showError("SMTP kimlik doğrulama hatası!\nKullanıcı adı veya şifre yanlış.");
                });
            } catch (javax.mail.MessagingException e) {
                Platform.runLater(() -> {
                    log("\\u274C SMTP bağlantı hatası: " + e.getMessage());
                    showError("SMTP bağlantı hatası:\n" + e.getMessage());
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    log("\\u274C SMTP hatası: " + e.getMessage());
                    showError("SMTP bağlantı hatası:\n" + e.getMessage());
                });
            }
        }).start();
    }

    private ComboBox<String> paymentProvider;
    private TextField paymentApiKey, paymentApiSecret, paymentWebhookSecret, paymentMerchantId;
    private ToggleSwitch paymentEnabledSwitch, paymentLiveModeSwitch;

    private VBox createPaymentSection() {
        Label title = new Label("💳 ÖDEME SİSTEMİ");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        paymentEnabledSwitch = new ToggleSwitch("Ödeme Sistemi Aktif");
        paymentEnabledSwitch.setSelected(prefs.getBoolean("payment.enabled", false));

        // OFF = Test Modu, ON = Canlı Mod (Satış)
        paymentLiveModeSwitch = new ToggleSwitch("TEST ◄─► CANLI");
        paymentLiveModeSwitch.setSelected(!prefs.getBoolean("payment.test", true)); // test=true means live=false
        paymentLiveModeSwitch.disableProperty().bind(paymentEnabledSwitch.selectedProperty().not());

        GridPane grid = new GridPane();
        grid.setHgap(15);
        grid.setVgap(10);

        // Provider
        paymentProvider = new ComboBox<>();
        paymentProvider.getItems().addAll("STRIPE", "PAYTR", "SHOPIER");
        paymentProvider.setValue(prefs.get("payment.provider", "STRIPE"));
        paymentProvider.setStyle("-fx-background-color: #16213e; -fx-mark-color: white;");
        paymentProvider.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(item);
                if (item != null) {
                    setStyle("-fx-background-color: #16213e; -fx-text-fill: white;");
                } else {
                    setStyle("-fx-background-color: #16213e;");
                }
            }
        });
        paymentProvider.setButtonCell(new ListCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(item);
                setStyle("-fx-text-fill: white; -fx-background-color: transparent;");
            }
        });
        grid.addRow(0, createLabel("Provider:"), paymentProvider);

        // Dynamic Labels
        Label apiKeyLabel = createLabel("API Key:");
        Label apiSecretLabel = createLabel("API Secret:");
        Label webhookLabel = createLabel("Webhook Secret:");
        Label merchantLabel = createLabel("Merchant ID:");
        Label callbackLabel = createLabel("Callback URL:");

        // API Key
        paymentApiKey = new TextField(prefs.get("payment.apiKey", ""));
        styleTextField(paymentApiKey);
        grid.addRow(1, apiKeyLabel, paymentApiKey);

        // API Secret
        paymentApiSecret = new PasswordField();
        paymentApiSecret.setText(prefs.get("payment.apiSecret", ""));
        styleTextField(paymentApiSecret);
        grid.addRow(2, apiSecretLabel, paymentApiSecret);

        // Webhook
        paymentWebhookSecret = new PasswordField();
        paymentWebhookSecret.setText(prefs.get("payment.webhook", ""));
        styleTextField(paymentWebhookSecret);
        grid.addRow(3, webhookLabel, paymentWebhookSecret);

        // Merchant ID
        paymentMerchantId = new TextField(prefs.get("payment.merchant", ""));
        styleTextField(paymentMerchantId);
        grid.addRow(4, merchantLabel, paymentMerchantId);

        // Callback URL (Read Only)
        TextField paymentCallbackUrl = new TextField();
        styleTextField(paymentCallbackUrl);
        paymentCallbackUrl.setEditable(false);
        grid.addRow(5, callbackLabel, paymentCallbackUrl);

        // Dynamic label updater
        Runnable updateLabels = () -> {
            String provider = paymentProvider.getValue();
            switch (provider) {
                case "STRIPE" -> {
                    apiKeyLabel.setText("Secret Key:");
                    apiSecretLabel.setText("—");
                    apiSecretLabel.setVisible(false);
                    paymentApiSecret.setVisible(false);
                    paymentApiSecret.setManaged(false);
                    apiSecretLabel.setManaged(false);
                    webhookLabel.setText("Webhook Secret:");
                    webhookLabel.setVisible(true);
                    paymentWebhookSecret.setVisible(true);
                    paymentWebhookSecret.setManaged(true);
                    webhookLabel.setManaged(true);
                    merchantLabel.setText("—");
                    merchantLabel.setVisible(false);
                    paymentMerchantId.setVisible(false);
                    paymentMerchantId.setManaged(false);
                    merchantLabel.setManaged(false);
                }
                case "PAYTR" -> {
                    apiKeyLabel.setText("Merchant Key:");
                    apiSecretLabel.setText("Merchant Salt:");
                    apiSecretLabel.setVisible(true);
                    paymentApiSecret.setVisible(true);
                    paymentApiSecret.setManaged(true);
                    apiSecretLabel.setManaged(true);
                    webhookLabel.setText("—");
                    webhookLabel.setVisible(false);
                    paymentWebhookSecret.setVisible(false);
                    paymentWebhookSecret.setManaged(false);
                    webhookLabel.setManaged(false);
                    merchantLabel.setText("Merchant ID:");
                    merchantLabel.setVisible(true);
                    paymentMerchantId.setVisible(true);
                    paymentMerchantId.setManaged(true);
                    merchantLabel.setManaged(true);
                }
                case "SHOPIER" -> {
                    apiKeyLabel.setText("API User:");
                    apiSecretLabel.setText("API Password:");
                    apiSecretLabel.setVisible(true);
                    paymentApiSecret.setVisible(true);
                    paymentApiSecret.setManaged(true);
                    apiSecretLabel.setManaged(true);
                    webhookLabel.setText("—");
                    webhookLabel.setVisible(false);
                    paymentWebhookSecret.setVisible(false);
                    paymentWebhookSecret.setManaged(false);
                    webhookLabel.setManaged(false);
                    merchantLabel.setText("—");
                    merchantLabel.setVisible(false);
                    paymentMerchantId.setVisible(false);
                    paymentMerchantId.setManaged(false);
                    merchantLabel.setManaged(false);

                    // Show Callback
                    callbackLabel.setText("Callback URL:");
                    callbackLabel.setVisible(true);
                    callbackLabel.setManaged(true);
                    paymentCallbackUrl.setVisible(true);
                    paymentCallbackUrl.setManaged(true);

                    String port = prefs.get("server.web_port", "8080");
                    String protocol = prefs.getBoolean("ssl.enabled", false) ? "https" : "http";
                    paymentCallbackUrl.setText(protocol + "://YOUR_IP:" + port + "/api/callbacks/shopier");
                }
                default -> {
                    callbackLabel.setVisible(false);
                    callbackLabel.setManaged(false);
                    paymentCallbackUrl.setVisible(false);
                    paymentCallbackUrl.setManaged(false);
                }
            }
        };

        paymentProvider.valueProperty().addListener((obs, oldVal, newVal) -> updateLabels.run());
        updateLabels.run(); // Initial state

        VBox section = new VBox(15, title, paymentEnabledSwitch, paymentLiveModeSwitch, grid);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;

    }

    // ==================== CUSTOM TOGGLE SWITCH ====================

    private static class ToggleSwitch extends HBox {
        private final javafx.beans.property.BooleanProperty selected = new javafx.beans.property.SimpleBooleanProperty();
        private final Circle trigger = new Circle(10);
        private final javafx.scene.shape.Rectangle background = new javafx.scene.shape.Rectangle(40, 20);

        public ToggleSwitch(String text) {
            super(10);
            setAlignment(Pos.CENTER_LEFT);

            Label label = new Label(text);
            label.setTextFill(Color.web("#8892b0"));
            label.setFont(Font.font("Segoe UI", 12));

            background.setArcWidth(20);
            background.setArcHeight(20);
            background.setFill(Color.web("#1f4068"));
            background.setStroke(Color.web("#444"));

            trigger.setFill(Color.WHITE);
            trigger.setStroke(Color.web("#444"));

            StackPane switchPane = new StackPane(background, trigger);
            StackPane.setAlignment(trigger, Pos.CENTER_LEFT);
            switchPane.setMaxSize(40, 20);

            getChildren().addAll(label, switchPane);

            setOnMouseClicked(event -> {
                selected.set(!selected.get());
            });

            selected.addListener((obs, oldVal, newVal) -> {
                updateState(newVal);
            });

            updateState(false); // Init
        }

        private void updateState(boolean active) {
            if (active) {
                background.setFill(Color.web("#00aa55"));
                StackPane.setAlignment(trigger, Pos.CENTER_RIGHT);
            } else {
                background.setFill(Color.web("#1f4068"));
                StackPane.setAlignment(trigger, Pos.CENTER_LEFT);
            }
        }

        public boolean isSelected() {
            return selected.get();
        }

        public void setSelected(boolean val) {
            selected.set(val);
        }

        public javafx.beans.property.BooleanProperty selectedProperty() {
            return selected;
        }
    }

    private void loadSettings() {
        String langCode = prefs.get("language", "tr");
        for (I18n.Language lang : I18n.Language.values()) {
            if (lang.getCode().equals(langCode)) {
                I18n.setLanguage(lang);
                break;
            }
        }
    }

    // ==================== UTILITIES ====================

    private Label createTabIcon(String icon) {
        Label label = new Label(icon);
        label.setFont(Font.font(16));
        return label;
    }

    private VBox createLogSection() {
        Label title = new Label("📋 Log");
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 12));
        title.setTextFill(Color.web("#8892b0"));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefHeight(750);
        logArea.setStyle("-fx-control-inner-background: #0f0f23; -fx-text-fill: #00ff88;");

        return new VBox(5, title, logArea);
    }

    private void log(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        Platform.runLater(() -> {
            logArea.appendText("[" + timestamp + "] " + message + "\n");
        });
    }

    private void connectDatabase() {
        String host = prefs.get("mysql.host", "localhost");
        int port = Integer.parseInt(prefs.get("mysql.port", "3306"));
        String db = prefs.get("mysql.database", "barron_licenses");
        String user = prefs.get("mysql.user", "barron");

        database.configure(host, port, db, user, "");

        if (prefs.getBoolean("failover.enabled", false)) {
            database.configureSecondary(
                    prefs.get("failover.host", ""),
                    Integer.parseInt(prefs.get("failover.port", "3306")),
                    prefs.get("failover.user", ""),
                    prefs.get("failover.pass", ""));
        }

        if (database.connect()) {
            try {
                database.initializeTables();
                log("✅ MySQL bağlantısı kuruldu");
                refreshPluginList();
                refreshLicenseTable();
            } catch (Exception e) {
                log("⚠️ Tablolar oluşturulamadı: " + e.getMessage());
            }
        } else {
            log("⚠️ MySQL bağlantısı kurulamadı. Ayarlar sayfasından yapılandırın.");
        }
    }

    private void copyToClipboard(String text) {
        javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
        content.putString(text);
        clipboard.setContent(content);
        log("Panoya kopyalandı: " + text);
    }

    private void showInfo(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(I18n.get("common.success"));
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(I18n.get("common.error"));
        alert.setContentText(message);
        alert.showAndWait();
    }

    @Override
    public void stop() {
        System.out.println("Stopping application...");
        dev.barron.server.LicenseServer.stop();
        if (database != null)
            database.close();
        Platform.exit();
        System.exit(0);
    }
}
