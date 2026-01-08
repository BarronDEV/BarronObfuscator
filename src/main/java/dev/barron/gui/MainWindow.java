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

/**
 * Barron License Manager - 4 Page Application
 * 
 * Page 1: Plugin Encryption (Normal / Server-Side toggle)
 * Page 2: License Generation
 * Page 3: License Management
 * Page 4: Settings (Language, MySQL, Load Balancer)
 */
public class MainWindow extends Application {

    private Stage primaryStage;
    private ObfuscationConfig config;
    private DatabaseManager database;
    private Preferences prefs;

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
        this.primaryStage = primaryStage;
        this.config = new ObfuscationConfig();
        this.database = new DatabaseManager();
        this.prefs = Preferences.userNodeForPackage(MainWindow.class);

        loadSettings();

        primaryStage.setTitle(Barron.NAME + " v" + Barron.VERSION);
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
        tab.setContent(content);
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
        dropLabel.setText("✅ " + file.getName());
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

        GridPane grid = new GridPane();
        grid.setHgap(30);
        grid.setVgap(8);
        grid.add(stringEncryptionCheck, 0, 0);
        grid.add(identifierRenamingCheck, 1, 0);
        grid.add(controlFlowCheck, 0, 1);
        grid.add(deadCodeCheck, 1, 1);
        grid.add(antiDebugCheck, 0, 2);
        grid.add(metadataRemovalCheck, 1, 2);

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
                    log("✅ Şifreleme tamamlandı!");
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
                    log("❌ HATA: " + getException().getMessage());
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
        pluginList.setStyle("-fx-background-color: #0a1628;");
        pluginList.setCellFactory(lv -> new ListCell<>() {
            @Override
            protected void updateItem(DatabaseManager.PluginInfo item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(String.format("%s [%d lisans]", item.filename(), item.licenseCount()));
                }
                setTextFill(Color.web("#00ff88"));
            }
        });

        pluginList.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) {
                createLicenseForSelected();
            }
        });

        Label hint = new Label("💡 " + I18n.get("license.doubleclick"));
        hint.setTextFill(Color.web("#666666"));

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

        content.getChildren().addAll(listTitle, pluginList, hint, durationTitle, durationBox, lastBox);
        tab.setContent(content);
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
            log("✅ Lisans oluşturuldu: " + licenseKey);

            refreshPluginList();
        } catch (Exception e) {
            log("❌ Lisans oluşturma hatası: " + e.getMessage());
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
            return new javafx.beans.property.SimpleStringProperty(days + " " + I18n.get("license.days"));
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

        content.getChildren().addAll(searchField, licenseTable, buttonBox);
        VBox.setVgrow(licenseTable, Priority.ALWAYS);
        tab.setContent(content);
        return tab;
    }

    private void refreshLicenseTable() {
        try {
            licenseTable.getItems().clear();
            licenseTable.getItems().addAll(database.getAllLicenses());
            log("Lisans listesi yenilendi");
        } catch (Exception e) {
            log("❌ " + e.getMessage());
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
                log("❌ " + e.getMessage());
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

        // MySQL
        VBox mysqlSection = createMySQLSection();

        // Load Balancer
        VBox lbSection = createLoadBalancerSection();

        // Save button
        Button saveBtn = new Button("💾 " + I18n.get("settings.save"));
        saveBtn.setStyle(
                "-fx-background-color: #00aa55; -fx-text-fill: white; -fx-font-weight: bold; -fx-padding: 15 40;");
        saveBtn.setOnAction(e -> saveSettings());

        HBox saveBox = new HBox(saveBtn);
        saveBox.setAlignment(Pos.CENTER);

        content.getChildren().addAll(langSection, mysqlSection, lbSection, saveBox);
        tab.setContent(content);
        return tab;
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

    private VBox createLoadBalancerSection() {
        Label title = new Label("⚖️ " + I18n.get("settings.loadbalancer"));
        title.setFont(Font.font("Segoe UI", FontWeight.BOLD, 14));
        title.setTextFill(Color.web("#e94560"));

        loadBalancerCheck = new CheckBox("Aktif");
        loadBalancerCheck.setTextFill(Color.web("#8892b0"));

        backupHost = new TextField();
        backupHost.setPromptText(I18n.get("settings.backup.host"));
        styleTextField(backupHost);
        backupHost.setDisable(true);

        loadBalancerCheck.setOnAction(e -> backupHost.setDisable(!loadBalancerCheck.isSelected()));

        Button copyBtn = new Button("📥 " + I18n.get("settings.backup.copy"));
        copyBtn.setStyle("-fx-background-color: #1f4068; -fx-text-fill: #8892b0;");
        copyBtn.setOnAction(e -> copyToBackup());

        VBox section = new VBox(10, title, loadBalancerCheck, backupHost, copyBtn);
        section.setPadding(new Insets(10));
        section.setStyle("-fx-background-color: #0a1628; -fx-background-radius: 10;");
        return section;
    }

    private void styleTextField(TextField tf) {
        tf.setStyle("-fx-background-color: #16213e; -fx-text-fill: #00ff88; -fx-border-color: #333;");
    }

    private Label createLabel(String text) {
        Label label = new Label(text);
        label.setTextFill(Color.web("#8892b0"));
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
            log("✅ MySQL bağlantısı başarılı!");
            showInfo("MySQL bağlantısı başarılı!");
        } else {
            log("❌ MySQL bağlantısı başarısız!");
            showError("MySQL bağlantısı başarısız!");
        }
    }

    private void copyToBackup() {
        if (backupHost.getText().isEmpty()) {
            showError("Yedek sunucu IP'si girin!");
            return;
        }

        try {
            database.replicateToBackup(
                    backupHost.getText(),
                    Integer.parseInt(mysqlPort.getText()),
                    mysqlUser.getText(),
                    mysqlPassword.getText());
            log("✅ Veriler yedek sunucuya kopyalandı!");
            showInfo("Veriler başarıyla kopyalandı!");
        } catch (Exception e) {
            log("❌ Kopyalama hatası: " + e.getMessage());
            showError("Kopyalama hatası: " + e.getMessage());
        }
    }

    private void saveSettings() {
        prefs.put("mysql.host", mysqlHost.getText());
        prefs.put("mysql.port", mysqlPort.getText());
        prefs.put("mysql.user", mysqlUser.getText());
        prefs.put("mysql.database", mysqlDatabase.getText());
        prefs.put("language", languageCombo.getValue().getCode());

        I18n.setLanguage(languageCombo.getValue());
        log("Ayarlar kaydedildi");
        showInfo("Ayarlar kaydedildi. Dil değişikliği için uygulamayı yeniden başlatın.");
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
        logArea.setPrefHeight(120);
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
}
