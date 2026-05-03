package dev.barron.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.barron.gui.MainWindow;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Secure MySQL Database Manager with Active-Passive Failover
 * 
 * Security features:
 * - BCrypt password hashing
 * - Prepared statements (SQL injection prevention)
 * - Connection pooling
 * - Real-time replication to secondary server
 * 
 * Failover:
 * - Primary handles all requests
 * - Secondary receives real-time data replication
 * - If primary fails, switch to secondary
 */
public class DatabaseManager {

    // Primary server
    private String host = "localhost";
    private int port = 3306;
    private String database = "barron_licenses";
    private String username = "barron";
    private String password = "";

    // Secondary server (failover)
    private boolean failoverEnabled = false;
    private String secondaryHost = "";
    private int secondaryPort = 3306;
    private String secondaryUser = "";
    private String secondaryPassword = "";

    // HikariCP Connection Pools
    private HikariDataSource dataSource;
    private HikariDataSource secondaryDataSource;

    // Connection pooling enabled - no static connection fields

    public DatabaseManager() {
        // SECRETS MANAGEMENT: Try to load from Environment Variables first
        if (System.getenv("DB_HOST") != null)
            this.host = System.getenv("DB_HOST");
        if (System.getenv("DB_PORT") != null)
            this.port = Integer.parseInt(System.getenv("DB_PORT"));
        if (System.getenv("DB_NAME") != null)
            this.database = System.getenv("DB_NAME");
        if (System.getenv("DB_USER") != null)
            this.username = System.getenv("DB_USER");
        if (System.getenv("DB_PASS") != null)
            this.password = System.getenv("DB_PASS");
    }

    public void configure(String host, int port, String database, String username, String password) {
        // Only override if not already set by Env Vars (or if explicitly re-configured)
        if (System.getenv("DB_HOST") == null) {
            this.host = host;
            this.port = port;
            this.database = database;
            this.username = username;
            this.password = password;
        }
    }

    public void configureSecondary(String host, int port, String user, String password) {
        this.secondaryHost = host;
        this.secondaryPort = port;
        this.secondaryUser = user;
        this.secondaryPassword = password;
        this.failoverEnabled = true;
    }

    // ==================== OPERATIONAL & TRANSACTIONS ====================

    /**
     * Backup Database logic (Simple mysqldump wrapper)
     * Returns true if successful
     */
    public boolean backupDatabase(String backupPath) {
        try {
            String filename = "backup_" + System.currentTimeMillis() + ".sql";
            String fullPath = backupPath + "/" + filename;

            // Note: This requires mysqldump to be in system PATH
            ProcessBuilder pb = new ProcessBuilder(
                    "mysqldump",
                    "-h" + host,
                    "-u" + username,
                    "-p" + password,
                    database,
                    "-r" + fullPath);

            pb.start().waitFor();
            System.out.println("[BACKUP] Database backed up to " + fullPath);
            return true;
        } catch (Exception e) {
            System.err.println("[BACKUP FAILED] " + e.getMessage());
            return false;
        }
    }

    /**
     * Transactional Order Completion
     * 1. Update Order Status
     * 2. Generate/Bind License (if applicable)
     * 3. Commit or Rollback
     */
    public boolean processOrderCompletion(String providerId) throws SQLException {
        // Find order ID
        String sql = "SELECT id FROM orders WHERE payment_provider_id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, providerId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    int orderId = rs.getInt("id");
                    return processOrderCompletion(orderId);
                }
            }
        }
        return false;
    }

    public boolean processOrderCompletion(int orderId) throws SQLException {
        MainWindow.globalLog("[ORDER] Processing order ID: " + orderId);

        // 1. Get Order
        String sqlOrder = "SELECT * FROM orders WHERE id = ?";
        OrderInfo order = null;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sqlOrder)) {
            stmt.setInt(1, orderId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                order = new OrderInfo(
                        rs.getInt("id"),
                        rs.getInt("user_id"),
                        rs.getInt("product_id"),
                        rs.getString("payment_provider"),
                        rs.getString("payment_provider_id"),
                        rs.getDouble("amount"),
                        rs.getString("currency"),
                        rs.getString("status"),
                        rs.getTimestamp("created_at"),
                        rs.getTimestamp("completed_at"));
            }
        }
        if (order == null) {
            MainWindow.globalLog("[ORDER] Order not found!");
            return false;
        }
        MainWindow.globalLog("[ORDER] Order found: user_id=" + order.userId() + ", product_id=" + order.productId()
                + ", status=" + order.status());

        if ("COMPLETED".equals(order.status())) {
            MainWindow.globalLog("[ORDER] Order already completed");
            return true; // Already done
        }

        // 2. Get Product
        ProductInfo product = getProduct(order.productId());
        if (product == null) {
            MainWindow.globalLog("[ORDER] Product not found for ID: " + order.productId());
            return false;
        }
        MainWindow.globalLog("[ORDER] Product: " + product.name() + ", actionType=" + product.actionType()
                + ", pluginId=" + product.pluginId());

        // 3. Fulfill
        boolean fulfilled = true;
        if ("LICENSE".equals(product.actionType())) {
            MainWindow.globalLog("[ORDER] Creating license...");
            // Generate License
            Integer pluginId = product.pluginId();
            if (pluginId != null) {
                // Create license (30 days)
                // Create license (30 days)
                String key = createLicense(pluginId, 30, product.id());
                MainWindow.globalLog("[ORDER] License key created: " + key);

                // Assign to user
                Integer lid = getLicenseId(key);
                MainWindow.globalLog("[ORDER] License ID: " + lid);
                if (lid != null) {
                    String sqlLink = "UPDATE licenses SET user_id = ? WHERE id = ?";
                    try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sqlLink)) {
                        stmt.setInt(1, order.userId());
                        stmt.setInt(2, lid);
                        stmt.executeUpdate();
                        MainWindow.globalLog("[ORDER] License assigned to user " + order.userId());
                    }
                } else {
                    MainWindow.globalLog("[ORDER] Failed to get license ID!");
                    fulfilled = false;
                }
            } else {
                MainWindow.globalLog("[ORDER] No plugin ID set for LICENSE product!");
                fulfilled = false; // LICENSE type but no plugin id?
            }
        } else if ("REDIRECT".equals(product.actionType())) {
            MainWindow.globalLog("[ORDER] REDIRECT action, nothing to do");
            // Nothing to do for backend
        }

        if (fulfilled) {
            updateOrderStatus(orderId, "COMPLETED", order.paymentProviderId());
            MainWindow.globalLog("[ORDER] Order completed successfully!");
        } else {
            MainWindow.globalLog("[ORDER] Order fulfillment FAILED!");
        }
        return fulfilled;
    }

    public boolean isFailoverEnabled() {
        return failoverEnabled;
    }

    public void setFailoverEnabled(boolean enabled) {
        this.failoverEnabled = enabled;
    }

    public String getSecondaryHost() {
        return secondaryHost;
    }

    public int getSecondaryPort() {
        return secondaryPort;
    }

    public String getSecondaryUser() {
        return secondaryUser;
    }

    public boolean connect() {
        try {
            // Close existing pool if any
            if (dataSource != null && !dataSource.isClosed()) {
                dataSource.close();
            }

            String url = String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC&autoReconnect=true&createDatabaseIfNotExist=true&allowPublicKeyRetrieval=true",
                    host, port, database);

            // Configure HikariCP
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(url);
            config.setUsername(username);
            config.setPassword(password);
            config.setPoolName("BarronPrimaryPool");

            // Pool Settings
            config.setMaximumPoolSize(10); // Max connections
            config.setMinimumIdle(2); // Min idle connections
            config.setIdleTimeout(300000); // 5 minutes idle timeout
            config.setMaxLifetime(600000); // 10 minutes max lifetime
            config.setConnectionTimeout(30000); // 30 seconds connection timeout
            config.setKeepaliveTime(60000); // 1 minute keepalive

            // Connection Validation
            config.setConnectionTestQuery("SELECT 1");

            // MySQL specific optimizations
            config.addDataSourceProperty("cachePrepStmts", "true");
            config.addDataSourceProperty("prepStmtCacheSize", "250");
            config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
            config.addDataSourceProperty("useServerPrepStmts", "true");

            dataSource = new HikariDataSource(config);
            System.out.println("[DB] HikariCP connection pool initialized successfully");

            // Also connect to secondary if enabled
            if (failoverEnabled && !secondaryHost.isEmpty()) {
                connectSecondary();
            }
            return true;
        } catch (Exception e) {
            System.err.println("[DB] Failed to initialize connection pool: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Ensures the connection is valid, refreshing from pool if needed.
     * Call this before using the connection field directly.
     */
    /**
     * Ensures the connection is valid.
     * Deprecated: HikariCP handles this automatically.
     */
    private void ensureConnection() throws SQLException {
        if (dataSource == null || dataSource.isClosed()) {
            throw new SQLException("Database connection pool is not initialized");
        }
    }

    /**
     * Get a connection from the pool.
     * IMPORTANT: Always use try-with-resources to ensure connection is returned to
     * pool.
     */
    public Connection getConnection() throws SQLException {
        if (dataSource == null || dataSource.isClosed()) {
            throw new SQLException("Database connection pool is not initialized");
        }
        return dataSource.getConnection();
    }

    public boolean isConnected() {
        if (dataSource == null || dataSource.isClosed()) {
            return false;
        }
        try (Connection conn = dataSource.getConnection()) {
            return conn.isValid(3);
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * Connect to secondary server for replication
     */
    public boolean connectSecondary() {
        if (secondaryHost.isEmpty())
            return false;
        try {
            // Close existing pool if any
            if (secondaryDataSource != null && !secondaryDataSource.isClosed()) {
                secondaryDataSource.close();
            }

            String url = String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC&autoReconnect=true&createDatabaseIfNotExist=true&allowPublicKeyRetrieval=true",
                    secondaryHost, secondaryPort, database);

            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(url);
            config.setUsername(secondaryUser);
            config.setPassword(secondaryPassword);
            config.setPoolName("BarronSecondaryPool");
            config.setMaximumPoolSize(5);
            config.setMinimumIdle(1);
            config.setIdleTimeout(300000);
            config.setMaxLifetime(600000);
            config.setConnectionTimeout(30000);
            config.setKeepaliveTime(60000);
            config.setConnectionTestQuery("SELECT 1");

            secondaryDataSource = new HikariDataSource(config);
            System.out.println("[DB] Secondary HikariCP pool initialized for replication");
            return true;
        } catch (Exception e) {
            System.err.println("[DB] Secondary pool initialization failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Replicate a SQL statement to secondary server (real-time)
     */
    private void replicateToSecondary(String sql, Object... params) {
        if (!failoverEnabled || secondaryDataSource == null || secondaryDataSource.isClosed())
            return;

        try (Connection conn = secondaryDataSource.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                stmt.setObject(i + 1, params[i]);
            }
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[DB] Replication failed: " + e.getMessage());
            // Don't throw - secondary failure shouldn't affect primary
        }
    }

    public boolean testConnection() {
        try (Connection testConn = DriverManager.getConnection(
                String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC",
                        host, port, database),
                username, password)) {
            return testConn.isValid(5);
        } catch (SQLException e) {
            return false;
        }
    }

    public boolean testSecondaryConnection() {
        if (secondaryHost.isEmpty())
            return false;
        try (Connection testConn = DriverManager.getConnection(
                String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC",
                        secondaryHost, secondaryPort, database),
                secondaryUser, secondaryPassword)) {
            return testConn.isValid(5);
        } catch (SQLException e) {
            return false;
        }
    }

    public void initializeTables() throws SQLException {
        String[] tables = {
                """
                        CREATE TABLE IF NOT EXISTS plugins (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(255) NOT NULL,
                            filename VARCHAR(255) NOT NULL,
                            version VARCHAR(50) NOT NULL,
                            file_hash VARCHAR(128),
                            encryption_mode VARCHAR(50),
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS payment_settings (
                            id INT PRIMARY KEY DEFAULT 1,
                            provider VARCHAR(50),
                            api_key VARCHAR(255),
                            api_secret VARCHAR(255),
                            webhook_secret VARCHAR(255),
                            merchant_id VARCHAR(255),
                            is_enabled BOOLEAN DEFAULT FALSE,
                            is_test_mode BOOLEAN DEFAULT TRUE,
                            stripe_active BOOLEAN DEFAULT FALSE,
                            paytr_active BOOLEAN DEFAULT FALSE,
                            shopier_active BOOLEAN DEFAULT FALSE
                        )
                        """,
                """
                        INSERT IGNORE INTO payment_settings (id) VALUES (1)
                        """,
                """
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            email VARCHAR(100) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            role ENUM('USER', 'ADMIN') DEFAULT 'USER',
                            csrf_token VARCHAR(64) NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP NULL,
                            is_active BOOLEAN DEFAULT TRUE
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS products (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            name VARCHAR(100) NOT NULL,
                            description TEXT,
                            price DECIMAL(10,2) NOT NULL,
                            currency VARCHAR(3) DEFAULT 'USD',
                            action_type ENUM('REDIRECT', 'LICENSE', 'CUSTOM') DEFAULT 'REDIRECT',
                            action_config TEXT,
                            plugin_id INT NULL,
                            file_path VARCHAR(500) NULL,
                            file_name VARCHAR(255) NULL,
                            is_active BOOLEAN DEFAULT TRUE,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE SET NULL
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS licenses (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            license_key VARCHAR(50) UNIQUE NOT NULL,
                            plugin_id INT NOT NULL,
                            user_id INT NULL,
                            expires_at TIMESTAMP NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            activated_at TIMESTAMP NULL,
                            last_seen TIMESTAMP NULL,
                            max_ips INT DEFAULT 2,
                            is_active BOOLEAN DEFAULT TRUE,
                            product_id INT NULL,
                            FOREIGN KEY (plugin_id) REFERENCES plugins(id),
                            FOREIGN KEY (user_id) REFERENCES users(id),
                            FOREIGN KEY (product_id) REFERENCES products(id)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS ips (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            license_id INT NOT NULL,
                            ip_address VARCHAR(128) NOT NULL,
                            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_used TIMESTAMP NULL,
                            FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE,
                            UNIQUE KEY unique_license_ip (license_id, ip_address)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS sessions (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            license_id INT NOT NULL,
                            ip_address VARCHAR(128) NOT NULL,
                            server_name VARCHAR(100),
                            last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
                        )
                        """,
                // ==================== NEW TABLES ====================
                // Products table moved up to satisfy FK constraints in Licenses
                """
                        CREATE TABLE IF NOT EXISTS orders (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            product_id INT NOT NULL,
                            payment_provider ENUM('STRIPE', 'SHOPIER', 'PAYTR', 'BALANCE') NOT NULL,
                            payment_provider_id VARCHAR(255) UNIQUE,
                            amount DECIMAL(10,2) NOT NULL,
                            currency VARCHAR(3) NOT NULL,
                            status ENUM('PENDING', 'COMPLETED', 'FAILED', 'REFUNDED') DEFAULT 'PENDING',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            completed_at TIMESTAMP NULL,
                            FOREIGN KEY (user_id) REFERENCES users(id),
                            FOREIGN KEY (product_id) REFERENCES products(id)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS admin_logs (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            admin_id INT NOT NULL,
                            action VARCHAR(50) NOT NULL,
                            target_type VARCHAR(50),
                            target_id INT,
                            details TEXT,
                            ip_address VARCHAR(128),
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (admin_id) REFERENCES users(id)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS password_resets (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            token VARCHAR(64) NOT NULL UNIQUE,
                            expires_at TIMESTAMP NOT NULL,
                            used BOOLEAN DEFAULT FALSE,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS license_ip_history (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            license_key VARCHAR(50) NOT NULL,
                            ip_address VARCHAR(128) NOT NULL,
                            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            access_count INT DEFAULT 1,
                            UNIQUE KEY unique_license_ip (license_key, ip_address),
                            INDEX idx_license_key (license_key),
                            INDEX idx_first_seen (first_seen)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS site_settings (
                            setting_key VARCHAR(50) PRIMARY KEY,
                            setting_value TEXT
                        )
                        """
        };

        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            for (String table : tables) {
                stmt.execute(table);
            }
        }

        // Add role column to existing users table if it doesn't exist
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role ENUM('USER', 'ADMIN') DEFAULT 'USER'");
            stmt.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS csrf_token VARCHAR(64) NULL");
            // New Features: Balance and 2FA
            stmt.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS balance DECIMAL(10,2) DEFAULT 0.00");
            stmt.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(32) NULL");
            stmt.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE");

            // FORCE fix: Ensure role column has correct default value (fixes older tables)
            stmt.execute("ALTER TABLE users MODIFY COLUMN role ENUM('USER', 'ADMIN') DEFAULT 'USER'");

            // Security Update: Widen IP columns for Extended HWID
            stmt.execute("ALTER TABLE ips MODIFY COLUMN ip_address VARCHAR(128)");
            stmt.execute("ALTER TABLE sessions MODIFY COLUMN ip_address VARCHAR(128)");
            stmt.execute("ALTER TABLE license_ip_history MODIFY COLUMN ip_address VARCHAR(128)");
            stmt.execute("ALTER TABLE admin_logs MODIFY COLUMN ip_address VARCHAR(128)");
        } catch (SQLException e) {
            // Column might already exist, ignore
            System.out.println("[DB INIT] Users column alter error (likely already exists): " + e.getMessage());
        }

        // Add missing columns to plugins table
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE plugins ADD COLUMN IF NOT EXISTS filename VARCHAR(255)");
            stmt.execute("ALTER TABLE plugins ADD COLUMN IF NOT EXISTS file_hash VARCHAR(128)");
            stmt.execute("ALTER TABLE plugins ADD COLUMN IF NOT EXISTS encryption_mode VARCHAR(50)");
            // Drop old file_path column if exists (no longer used)
            stmt.execute("ALTER TABLE plugins DROP COLUMN IF EXISTS file_path");
            // Rename uploaded_at to created_at for consistency (if it exists)
            stmt.execute("ALTER TABLE plugins ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
        } catch (SQLException e) {
            System.out.println("[DB INIT] Plugins column alter error (likely already exists): " + e.getMessage());
        }

        // Fix orders table payment_provider ENUM to include BALANCE
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(
                    "ALTER TABLE orders MODIFY COLUMN payment_provider ENUM('STRIPE', 'SHOPIER', 'PAYTR', 'BALANCE') NOT NULL");
        } catch (SQLException e) {
            System.out.println("[DB INIT] Orders payment_provider alter error: " + e.getMessage());
        }

        // Add file columns to products table
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS file_path VARCHAR(500) NULL");
            stmt.execute("ALTER TABLE products ADD COLUMN IF NOT EXISTS file_name VARCHAR(255) NULL");
        } catch (SQLException e) {
            System.out.println("[DB INIT] Products file column alter error: " + e.getMessage());
        }

        // Add product_id column to licenses table
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS product_id INT NULL");
            // Note: Foreign key addition might fail if index names conflict or constraint
            // exists.
            // A robust solution checks verifyFK but for now we try/catch.
            try {
                stmt.execute(
                        "ALTER TABLE licenses ADD CONSTRAINT fk_licenses_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL");
            } catch (SQLException ex) {
                // Ignore if constraint already exists
            }
        } catch (SQLException e) {
            System.out.println("[DB INIT] Licenses product_id alter error: " + e.getMessage());
        }
    }

    // ==================== PLUGINS ====================

    public int addPlugin(String name, String filename, String version, String fileHash, String mode)
            throws SQLException {
        String sql = "INSERT INTO plugins (name, filename, version, file_hash, encryption_mode) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, name);
            stmt.setString(2, filename);
            stmt.setString(3, version);
            stmt.setString(4, fileHash);
            stmt.setString(5, mode);
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return -1;
    }

    public List<PluginInfo> getAllPlugins() throws SQLException {
        List<PluginInfo> plugins = new ArrayList<>();
        String sql = """
                SELECT p.*, COUNT(l.id) as license_count
                FROM plugins p
                LEFT JOIN licenses l ON p.id = l.plugin_id
                GROUP BY p.id
                """;
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                plugins.add(new PluginInfo(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("filename"),
                        rs.getString("version"),
                        rs.getInt("license_count"),
                        rs.getTimestamp("created_at")));
            }
        }
        return plugins;
    }

    public Integer getPluginId(String name) throws SQLException {
        String sql = "SELECT id FROM plugins WHERE name = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, name);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }
        }
        return null;
    }

    public void deletePlugin(int pluginId) throws SQLException {
        // First delete all associated licenses (which will cascade to ips and sessions)
        String deleteLicensesSql = "DELETE FROM licenses WHERE plugin_id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(deleteLicensesSql)) {
            stmt.setInt(1, pluginId);
            stmt.executeUpdate();
        }

        // Then delete the plugin
        String sql = "DELETE FROM plugins WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, pluginId);
            stmt.executeUpdate();
        }

        // Replicate to secondary if enabled
        replicateToSecondary(deleteLicensesSql, pluginId);
        replicateToSecondary(sql, pluginId);
    }

    // ==================== LICENSES ====================

    public String generateLicenseKey() {
        String uuid = UUID.randomUUID().toString().toUpperCase().replace("-", "");
        return uuid.substring(0, 4) + "-" + uuid.substring(4, 8) + "-" +
                uuid.substring(8, 12) + "-" + uuid.substring(12, 16);
    }

    public String createLicense(int pluginId, Integer daysValid) throws SQLException {
        return createLicense(pluginId, daysValid, null);
    }

    public String createLicense(int pluginId, Integer daysValid, Integer productId) throws SQLException {
        String licenseKey;
        // Ensure unique key
        do {
            licenseKey = generateLicenseKey();
        } while (licenseExists(licenseKey));

        String sql = "INSERT INTO licenses (license_key, plugin_id, expires_at, product_id) VALUES (?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            stmt.setInt(2, pluginId);
            if (daysValid != null && daysValid > 0) {
                stmt.setTimestamp(3,
                        new Timestamp(System.currentTimeMillis() + (long) daysValid * 24 * 60 * 60 * 1000));
            } else {
                stmt.setNull(3, Types.TIMESTAMP);
            }
            stmt.setObject(4, productId);
            stmt.executeUpdate();
        }
        return licenseKey;
    }

    public boolean licenseExists(String licenseKey) throws SQLException {
        String sql = "SELECT 1 FROM licenses WHERE license_key = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            return stmt.executeQuery().next();
        }
    }

    public Integer getLicenseId(String licenseKey) throws SQLException {
        String sql = "SELECT id FROM licenses WHERE license_key = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }
        }
        return null;
    }

    public List<LicenseInfo> getAllLicenses() throws SQLException {
        List<LicenseInfo> licenses = new ArrayList<>();
        String sql = """
                SELECT l.*, u.username, u.email, p.name as plugin_name,
                       (SELECT COUNT(*) FROM ips WHERE license_id = l.id) as ip_count,
                       (SELECT GROUP_CONCAT(ip_address) FROM ips WHERE license_id = l.id) as ip_list,
                       (SELECT MAX(last_heartbeat) FROM sessions WHERE license_id = l.id
                        AND last_heartbeat > DATE_SUB(NOW(), INTERVAL 5 MINUTE)) as is_online
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                LEFT JOIN plugins p ON l.plugin_id = p.id
                ORDER BY l.created_at DESC
                """;
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                licenses.add(new LicenseInfo(
                        rs.getInt("id"),
                        rs.getString("license_key"),
                        rs.getString("plugin_name"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("ip_list"),
                        rs.getTimestamp("expires_at"),
                        rs.getTimestamp("last_seen"),
                        rs.getTimestamp("is_online") != null,
                        rs.getBoolean("is_active"),
                        (Integer) rs.getObject("product_id"))); // Added productId
            }
        }
        return licenses;
    }

    public void deleteLicense(int licenseId) throws SQLException {
        String sql = "DELETE FROM licenses WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, licenseId);
            stmt.executeUpdate();
        }
    }

    // ==================== USERS ====================

    public boolean registerUser(String username, String email, String password) throws SQLException {
        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        String sql = "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'USER')";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, email);
            stmt.setString(3, passwordHash);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) { // Duplicate entry
                return false;
            }
            throw e;
        }
    }

    public Integer authenticateUser(String usernameOrEmail, String password) throws SQLException {
        String sql = "SELECT id, password_hash, is_active FROM users WHERE (username = ? OR email = ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, usernameOrEmail);
            stmt.setString(2, usernameOrEmail);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int id = rs.getInt("id");
                String hash = rs.getString("password_hash");
                boolean isActive = rs.getBoolean("is_active");

                if (!isActive) {
                    return null; // User is inactive
                }

                if (hash == null || hash.isEmpty()) {
                    return null; // No password set
                }

                if (BCrypt.checkpw(password, hash)) {
                    updateLastLogin(id);
                    return id;
                }
            }
        }
        return null;
    }

    // ==================== USER DASHBOARD METHODS ====================

    private void updateLastLogin(int userId) throws SQLException {
        String sql = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.executeUpdate();
        }
    }

    public boolean bindLicenseToUser(int userId, String licenseKey) throws SQLException {
        // Check if license exists and is unclaimed
        String checkSql = "SELECT id, user_id FROM licenses WHERE license_key = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(checkSql)) {
            stmt.setString(1, licenseKey);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                if (rs.getObject("user_id") != null) {
                    return false; // Already claimed
                }
                int licenseId = rs.getInt("id");

                String updateSql = "UPDATE licenses SET user_id = ? WHERE id = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setInt(1, userId);
                    updateStmt.setInt(2, licenseId);
                    return updateStmt.executeUpdate() > 0;
                }
            }
        }
        return false; // License not found
    }

    /**
     * Get user email by user ID
     */
    public String getEmailForUser(int userId) throws SQLException {
        ensureConnection();
        String sql = "SELECT email FROM users WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("email");
                }
            }
        }
        return null;
    }

    /**
     * Get product name for a license key (via plugin or product)
     */
    public String getProductNameForLicense(String licenseKey) throws SQLException {
        ensureConnection();
        // Try to get product name from products table first (if linked)
        String sql = """
                SELECT COALESCE(pr.name, p.name) as product_name
                FROM licenses l
                LEFT JOIN plugins p ON l.plugin_id = p.id
                LEFT JOIN products pr ON l.product_id = pr.id
                WHERE l.license_key = ?
                """;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("product_name");
                }
            }
        }
        return null;
    }

    /**
     * Tracks IP access for a license and returns unique IP count in last 24h
     */
    public int trackLicenseIpAccess(String licenseKey, String ipAddress) throws SQLException {
        try (Connection conn = getConnection()) {
            // 1. Insert or update history
            String upsertSql = """
                    INSERT INTO license_ip_history (license_key, ip_address, last_seen, access_count)
                    VALUES (?, ?, NOW(), 1)
                    ON DUPLICATE KEY UPDATE
                        last_seen = NOW(),
                        access_count = access_count + 1
                    """;

            try (PreparedStatement stmt = conn.prepareStatement(upsertSql)) {
                stmt.setString(1, licenseKey);
                stmt.setString(2, ipAddress);
                stmt.executeUpdate();
            }

            // 2. Count unique IPs in last 24 hours
            String countSql = """
                    SELECT COUNT(DISTINCT ip_address)
                    FROM license_ip_history
                    WHERE license_key = ?
                    AND last_seen > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    """;

            try (PreparedStatement stmt = conn.prepareStatement(countSql)) {
                stmt.setString(1, licenseKey);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            }
        }
        return 0;
    }

    public List<LicenseInfo> getLicensesForUser(int userId) throws SQLException {
        List<LicenseInfo> licenses = new ArrayList<>();
        String sql = """
                SELECT l.*, u.username, u.email, p.name as plugin_name,
                       (SELECT COUNT(*) FROM ips WHERE license_id = l.id) as ip_count,
                       (SELECT GROUP_CONCAT(ip_address) FROM ips WHERE license_id = l.id) as ip_list,
                       (SELECT MAX(last_heartbeat) FROM sessions WHERE license_id = l.id
                        AND last_heartbeat > DATE_SUB(NOW(), INTERVAL 5 MINUTE)) as is_online
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                LEFT JOIN plugins p ON l.plugin_id = p.id
                WHERE l.user_id = ?
                ORDER BY l.created_at DESC
                """;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    licenses.add(new LicenseInfo(
                            rs.getInt("id"),
                            rs.getString("license_key"),
                            rs.getString("plugin_name"),
                            rs.getString("username"),
                            rs.getString("email"),
                            rs.getString("ip_list"),
                            rs.getTimestamp("expires_at"),
                            rs.getTimestamp("last_seen"),
                            rs.getTimestamp("is_online") != null,
                            rs.getBoolean("is_active"),
                            (Integer) rs.getObject("product_id"))); // Added productId
                }
            }
        }
        return licenses;
    }

    public boolean updateUser(int userId, String email, String password) throws SQLException {
        StringBuilder sql = new StringBuilder("UPDATE users SET email = ?");
        if (password != null && !password.isEmpty()) {
            sql.append(", password_hash = ?");
        }
        sql.append(" WHERE id = ?");

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
            stmt.setString(1, email);
            int idx = 2;
            if (password != null && !password.isEmpty()) {
                stmt.setString(idx++, BCrypt.hashpw(password, BCrypt.gensalt(12)));
            }
            stmt.setInt(idx, userId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062)
                return false; // Duplicate email
            throw e;
        }
    }

    public UserInfo getUser(int userId) throws SQLException {
        String sql = "SELECT id, username, email, role, balance, two_factor_enabled, two_factor_secret FROM users WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new UserInfo(rs.getInt("id"), rs.getString("username"),
                            rs.getString("email"), rs.getString("role"),
                            rs.getDouble("balance"), rs.getBoolean("two_factor_enabled"),
                            rs.getString("two_factor_secret"));
                }
            }
        }
        return null;
    }

    public void setLicenseIps(int licenseId, List<String> ips) throws SQLException {
        // Transaction to ensure atomicity
        try (Connection conn = getConnection()) {
            boolean autoCommit = conn.getAutoCommit();
            try {
                conn.setAutoCommit(false);

                // 1. Delete existing IPs
                String deleteSql = "DELETE FROM ips WHERE license_id = ?";
                try (PreparedStatement del = conn.prepareStatement(deleteSql)) {
                    del.setInt(1, licenseId);
                    del.executeUpdate();
                }

                // 2. Insert new IPs (max 2 enforced by loop limit from caller, but ideally here
                // too)
                String insertSql = "INSERT INTO ips (license_id, ip_address) VALUES (?, ?)";
                try (PreparedStatement ins = conn.prepareStatement(insertSql)) {
                    for (String ip : ips) {
                        if (ip == null || ip.isBlank())
                            continue;
                        ins.setInt(1, licenseId);
                        ins.setString(2, ip.trim());
                        ins.executeUpdate();
                    }
                }

                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(autoCommit);
            }
        }
    }

    // ==================== IP MANAGEMENT ====================

    public boolean addIpToLicense(int licenseId, String ipAddress) throws SQLException {
        // Check max IPs
        String countSql = "SELECT COUNT(*), max_ips FROM licenses l LEFT JOIN ips i ON l.id = i.license_id WHERE l.id = ? GROUP BY l.id";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(countSql)) {
            stmt.setInt(1, licenseId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                if (rs.getInt(1) >= rs.getInt(2)) {
                    return false; // Max IPs reached
                }
            }
        }

        String sql = "INSERT INTO ips (license_id, ip_address) VALUES (?, ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, licenseId);
            stmt.setString(2, ipAddress);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) { // Duplicate
                return false;
            }
            throw e;
        }
    }

    public void removeIpFromLicense(int licenseId, String ipAddress) throws SQLException {
        String sql = "DELETE FROM ips WHERE license_id = ? AND ip_address = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, licenseId);
            stmt.setString(2, ipAddress);
            stmt.executeUpdate();
        }
    }

    // ==================== VALIDATION ====================

    public boolean validateLicense(String licenseKey, String ipAddress) throws SQLException {
        String sql = """
                SELECT l.id, l.expires_at, l.is_active, i.ip_address
                FROM licenses l
                LEFT JOIN ips i ON l.id = i.license_id AND i.ip_address = ?
                WHERE l.license_key = ? AND l.is_active = TRUE
                """;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, ipAddress);
            stmt.setString(2, licenseKey);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                // Check if IP is registered
                if (rs.getString("ip_address") == null) {
                    return false; // IP not registered
                }

                // Check expiry
                Timestamp expires = rs.getTimestamp("expires_at");
                if (expires != null && expires.before(new Timestamp(System.currentTimeMillis()))) {
                    return false; // Expired
                }

                // Update last seen
                updateLastSeen(rs.getInt("id"));
                return true;
            }
        }
        return false;
    }

    public boolean tryAuthLicense(String licenseKey, String hwid) throws SQLException {
        String sql = """
                SELECT l.id, l.expires_at, l.is_active, l.max_ips, i.ip_address
                FROM licenses l
                LEFT JOIN ips i ON l.id = i.license_id AND i.ip_address = ?
                WHERE l.license_key = ? AND l.is_active = TRUE
                """;

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, hwid);
            stmt.setString(2, licenseKey);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                // Check expiry
                Timestamp expires = rs.getTimestamp("expires_at");
                if (expires != null && expires.before(new Timestamp(System.currentTimeMillis()))) {
                    return false; // Expired
                }

                // Check if HWID is already registered (Exact match)
                if (rs.getString("ip_address") != null) {
                    updateLastSeen(rs.getInt("id"));
                    return true;
                }

                // Not registered: Check Max IPs limit
                int licenseId = rs.getInt("id");
                int maxIps = rs.getInt("max_ips");

                // Count current IPs
                String countSql = "SELECT COUNT(*) FROM ips WHERE license_id = ?";
                try (PreparedStatement countStmt = conn.prepareStatement(countSql)) {
                    countStmt.setInt(1, licenseId);
                    ResultSet countRs = countStmt.executeQuery();
                    if (countRs.next()) {
                        int currentCount = countRs.getInt(1);
                        if (currentCount < maxIps) {
                            // Slot available: Auto-Lock this HWID
                            addIpToLicense(licenseId, hwid);
                            updateLastSeen(licenseId);
                            // Also log it
                            logAdminAction(1, "AUTO_LOCK_HWID", "LICENSE", licenseId, hwid, "SYSTEM");
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private void updateLastSeen(int licenseId) throws SQLException {
        String sql = "UPDATE licenses SET last_seen = CURRENT_TIMESTAMP WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, licenseId);
            stmt.executeUpdate();
        }
    }

    public void updateHeartbeat(String licenseKey, String ipAddress, String serverName) throws SQLException {
        String sql = """
                INSERT INTO sessions (license_id, ip_address, server_name, last_heartbeat)
                SELECT l.id, ?, ?, CURRENT_TIMESTAMP FROM licenses l WHERE l.license_key = ?
                ON DUPLICATE KEY UPDATE last_heartbeat = CURRENT_TIMESTAMP, server_name = ?
                """;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, ipAddress);
            stmt.setString(2, serverName);
            stmt.setString(3, licenseKey);
            stmt.setString(4, serverName);
            stmt.executeUpdate();
        }
    }

    // ==================== LOAD BALANCER ====================

    public void replicateToBackup(String backupHost, int backupPort, String backupUser, String backupPassword)
            throws SQLException {
        // Copy all data to backup server
        String backupUrl = String.format("jdbc:mysql://%s:%d/%s?useSSL=true",
                backupHost, backupPort, database);

        try (Connection backupConn = DriverManager.getConnection(backupUrl, backupUser, backupPassword)) {
            // Get all tables and copy data
            String[] tables = { "plugins", "users", "licenses", "ips", "sessions" };

            for (String table : tables) {
                // Get data from current
                String selectSql = "SELECT * FROM " + table;
                try (Connection conn = getConnection();
                        Statement selectStmt = conn.createStatement();
                        ResultSet rs = selectStmt.executeQuery(selectSql)) {

                    ResultSetMetaData meta = rs.getMetaData();
                    int columnCount = meta.getColumnCount();

                    // Delete existing data in backup
                    try (Statement deleteStmt = backupConn.createStatement()) {
                        deleteStmt.execute("DELETE FROM " + table);
                    }

                    // Build insert statement
                    StringBuilder insertSql = new StringBuilder("INSERT INTO " + table + " VALUES (");
                    for (int i = 0; i < columnCount; i++) {
                        insertSql.append(i > 0 ? ",?" : "?");
                    }
                    insertSql.append(")");

                    try (PreparedStatement insertStmt = backupConn.prepareStatement(insertSql.toString())) {
                        while (rs.next()) {
                            for (int i = 1; i <= columnCount; i++) {
                                insertStmt.setObject(i, rs.getObject(i));
                            }
                            insertStmt.addBatch();
                        }
                        insertStmt.executeBatch();
                    }
                }
            }
        }
    }

    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
        }
        if (secondaryDataSource != null && !secondaryDataSource.isClosed()) {
            secondaryDataSource.close();
        }
    }

    // ==================== DATA CLASSES ====================

    public record PluginInfo(int id, String name, String filename, String version,
            int licenseCount, Timestamp createdAt) {
        public int id() {
            return id;
        }

        public String filename() {
            return filename;
        }

        public int licenseCount() {
            return licenseCount;
        }
    }

    public record LicenseInfo(int id, String licenseKey, String pluginName,
            String username, String email, String ipList,
            Timestamp expiresAt, Timestamp lastSeen,
            boolean isOnline, boolean isActive, Integer productId) { // Added productId
        public int id() {
            return id;
        }

        public String licenseKey() {
            return licenseKey;
        }

        public String email() {
            return email;
        }

        public String ipList() {
            return ipList;
        }

        public Timestamp expiresAt() {
            return expiresAt;
        }

        public boolean isOnline() {
            return isOnline;
        }

        public Integer productId() {
            return productId;
        }
    }

    public record UserInfo(int id, String username, String email, String role, double balance,
            boolean twoFactorEnabled, String twoFactorSecret) {
        public int id() {
            return id;
        }

        public String username() {
            return username;
        }

        public String email() {
            return email;
        }

        public String role() {
            return role;
        }

        public double balance() {
            return balance;
        }

        public boolean twoFactorEnabled() {
            return twoFactorEnabled;
        }

        public String twoFactorSecret() {
            return twoFactorSecret;
        }
    }

    public record ProductInfo(int id, String name, String description, double price,
            String currency, String actionType, String actionConfig, Integer pluginId,
            String filePath, String fileName, boolean isActive, Timestamp createdAt) {
        public int id() {
            return id;
        }

        public String name() {
            return name;
        }

        public String description() {
            return description;
        }

        public double price() {
            return price;
        }

        public String currency() {
            return currency;
        }

        public String actionType() {
            return actionType;
        }

        public String actionConfig() {
            return actionConfig;
        }

        public Integer pluginId() {
            return pluginId;
        }

        public String filePath() {
            return filePath;
        }

        public String fileName() {
            return fileName;
        }

        public boolean isActive() {
            return isActive;
        }

        public Timestamp createdAt() {
            return createdAt;
        }
    }

    public record OrderInfo(int id, int userId, int productId, String paymentProvider,
            String paymentProviderId, double amount, String currency, String status,
            Timestamp createdAt, Timestamp completedAt) {
        public int id() {
            return id;
        }

        public int userId() {
            return userId;
        }

        public int productId() {
            return productId;
        }

        public String paymentProvider() {
            return paymentProvider;
        }

        public String paymentProviderId() {
            return paymentProviderId;
        }

        public double amount() {
            return amount;
        }

        public String currency() {
            return currency;
        }

        public String status() {
            return status;
        }

        public Timestamp createdAt() {
            return createdAt;
        }

        public Timestamp completedAt() {
            return completedAt;
        }
    }

    public record PaymentSettingsInfo(String provider, String apiKey, String apiSecret,
            String webhookSecret, String merchantId, boolean isEnabled, boolean isTestMode,
            boolean stripeActive, boolean paytrActive, boolean shopierActive) {
        public String provider() {
            return provider;
        }

        public String apiKey() {
            return apiKey;
        }

        public String apiSecret() {
            return apiSecret;
        }

        public String webhookSecret() {
            return webhookSecret;
        }

        public String merchantId() {
            return merchantId;
        }

        public boolean isEnabled() {
            return isEnabled;
        }

        public boolean isTestMode() {
            return isTestMode;
        }

        public boolean stripeActive() {
            return stripeActive;
        }

        public boolean paytrActive() {
            return paytrActive;
        }

        public boolean shopierActive() {
            return shopierActive;
        }
    }

    public record AdminLogInfo(int id, int adminId, String adminUsername, String action,
            String targetType, Integer targetId, String details, String ipAddress,
            Timestamp createdAt) {
        public int id() {
            return id;
        }

        public int adminId() {
            return adminId;
        }

        public String adminUsername() {
            return adminUsername;
        }

        public String action() {
            return action;
        }

        public String targetType() {
            return targetType;
        }

        public Integer targetId() {
            return targetId;
        }

        public String details() {
            return details;
        }

        public String ipAddress() {
            return ipAddress;
        }

        public Timestamp createdAt() {
            return createdAt;
        }
    }

    // ==================== INPUT VALIDATION ====================

    public boolean usernameExists(String username) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE username = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            return stmt.executeQuery().next();
        }
    }

    public boolean emailExists(String email) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE email = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            return stmt.executeQuery().next();
        }
    }

    public boolean usernameExistsExcludingUser(String username, int userId) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE username = ? AND id != ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setInt(2, userId);
            return stmt.executeQuery().next();
        }
    }

    public boolean emailExistsExcludingUser(String email, int userId) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE email = ? AND id != ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            stmt.setInt(2, userId);
            return stmt.executeQuery().next();
        }
    }

    // ==================== ADMIN METHODS ====================

    public boolean isAdmin(int userId) throws SQLException {
        String sql = "SELECT role FROM users WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return "ADMIN".equals(rs.getString("role"));
                }
            }
        }
        return false;
    }

    /**
     * Get table counts efficiently using COUNT(*) queries instead of loading full
     * tables.
     * Returns a map with keys: users, licenses, products, orders
     */
    public Map<String, Long> getStatsCounts() throws SQLException {
        Map<String, Long> counts = new HashMap<>();
        String sql = """
                SELECT
                    (SELECT COUNT(*) FROM users) as user_count,
                    (SELECT COUNT(*) FROM licenses) as license_count,
                    (SELECT COUNT(*) FROM products) as product_count,
                    (SELECT COUNT(*) FROM orders) as order_count
                """;
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                counts.put("users", rs.getLong("user_count"));
                counts.put("licenses", rs.getLong("license_count"));
                counts.put("products", rs.getLong("product_count"));
                counts.put("orders", rs.getLong("order_count"));
            }
        }
        return counts;
    }

    public void addBalance(int userId, double amount) throws SQLException {
        String sql = "UPDATE users SET balance = balance + ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setDouble(1, amount);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
    }

    public boolean deductBalance(int userId, double amount) throws SQLException {
        // Atomic deduction with check
        String sql = "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setDouble(1, amount);
            stmt.setInt(2, userId);
            stmt.setDouble(3, amount);
            return stmt.executeUpdate() > 0;
        }
    }

    public void setBalance(int userId, double balance) throws SQLException {
        String sql = "UPDATE users SET balance = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setDouble(1, balance);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
    }

    public void setUserRole(int userId, String role) throws SQLException {
        String sql = "UPDATE users SET role = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, role);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
        replicateToSecondary(sql, role, userId);
    }

    public void updateCsrfToken(int userId, String token) throws SQLException {
        String sql = "UPDATE users SET csrf_token = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, token);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
    }

    public void update2FA(int userId, String secret, boolean enabled) throws SQLException {
        String sql = "UPDATE users SET two_factor_secret = ?, two_factor_enabled = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, secret);
            stmt.setBoolean(2, enabled);
            stmt.setInt(3, userId);
            stmt.executeUpdate();
        }
    }

    public boolean validateCsrfToken(int userId, String token) throws SQLException {
        String sql = "SELECT csrf_token FROM users WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String stored = rs.getString("csrf_token");
                    return stored != null && stored.equals(token);
                }
            }
        }
        return false;
    }

    public List<UserInfo> getAllUsers() throws SQLException {
        List<UserInfo> users = new ArrayList<>();
        String sql = "SELECT id, username, email, role, balance, two_factor_enabled FROM users ORDER BY id";
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                users.add(new UserInfo(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("role"),
                        rs.getDouble("balance"),
                        rs.getBoolean("two_factor_enabled"),
                        null)); // Never expose 2FA secret via API
            }
        }
        return users;
    }

    public List<UserInfo> searchUsers(String query) throws SQLException {
        List<UserInfo> users = new ArrayList<>();
        String sql = "SELECT id, username, email, role, balance, two_factor_enabled FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, "%" + query + "%");
            stmt.setString(2, "%" + query + "%");
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    users.add(new UserInfo(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("email"),
                            rs.getString("role"),
                            rs.getDouble("balance"),
                            rs.getBoolean("two_factor_enabled"),
                            null)); // Never expose 2FA secret via API
                }
            }
        }
        return users;
    }

    public void deleteUser(int userId) throws SQLException {
        String sql = "DELETE FROM users WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.executeUpdate();
        }
        replicateToSecondary(sql, userId);
    }

    public void setUserActive(int userId, boolean active) throws SQLException {
        String sql = "UPDATE users SET is_active = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
        replicateToSecondary(sql, active, userId);
    }

    public boolean updateUserWithUsername(int userId, String username, String email, String password)
            throws SQLException {
        // Check for duplicates
        if (usernameExistsExcludingUser(username, userId)) {
            return false;
        }
        if (emailExistsExcludingUser(email, userId)) {
            return false;
        }

        StringBuilder sql = new StringBuilder("UPDATE users SET username = ?, email = ?");
        if (password != null && !password.isEmpty()) {
            sql.append(", password_hash = ?");
        }
        sql.append(" WHERE id = ?");

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
            stmt.setString(1, username);
            stmt.setString(2, email);
            int idx = 3;
            if (password != null && !password.isEmpty()) {
                stmt.setString(idx++, BCrypt.hashpw(password, BCrypt.gensalt(12)));
            }
            stmt.setInt(idx, userId);
            return stmt.executeUpdate() > 0;
        }
    }

    // ==================== CSRF TOKEN ====================

    public String generateAndSaveCsrfToken(int userId) throws SQLException {
        String token = UUID.randomUUID().toString().replace("-", "");
        String sql = "UPDATE users SET csrf_token = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, token);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
        return token;
    }

    // ==================== PRODUCT METHODS ====================

    public int addProduct(String name, String description, double price, String currency,
            String actionType, String actionConfig, Integer pluginId) throws SQLException {
        String sql = "INSERT INTO products (name, description, price, currency, action_type, action_config, plugin_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, name);
            stmt.setString(2, description);
            stmt.setDouble(3, price);
            stmt.setString(4, currency);
            stmt.setString(5, actionType);
            stmt.setString(6, actionConfig);
            if (pluginId != null) {
                stmt.setInt(7, pluginId);
            } else {
                stmt.setNull(7, Types.INTEGER);
            }
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return -1;
    }

    public boolean updateProduct(int productId, String name, String description, double price,
            String currency, String actionType, String actionConfig, Integer pluginId, boolean isActive)
            throws SQLException {
        String sql = "UPDATE products SET name = ?, description = ?, price = ?, currency = ?, action_type = ?, action_config = ?, plugin_id = ?, is_active = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, name);
            stmt.setString(2, description);
            stmt.setDouble(3, price);
            stmt.setString(4, currency);
            stmt.setString(5, actionType);
            stmt.setString(6, actionConfig);
            if (pluginId != null) {
                stmt.setInt(7, pluginId);
            } else {
                stmt.setNull(7, Types.INTEGER);
            }
            stmt.setBoolean(8, isActive);
            stmt.setInt(9, productId);
            return stmt.executeUpdate() > 0;
        }
    }

    public void deleteProduct(int productId) throws SQLException {
        // Soft delete to prevent FK violations with orders/licenses
        String sql = "UPDATE products SET is_active = FALSE WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, productId);
            stmt.executeUpdate();
        }
    }

    public boolean setProductFile(int productId, String filePath, String fileName) throws SQLException {
        String sql = "UPDATE products SET file_path = ?, file_name = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, filePath);
            stmt.setString(2, fileName);
            stmt.setInt(3, productId);
            int rows = stmt.executeUpdate();
            replicateToSecondary(sql, filePath, fileName, productId);
            return rows > 0;
        }
    }

    public List<ProductInfo> getAllProducts() throws SQLException {
        List<ProductInfo> products = new ArrayList<>();
        String sql = "SELECT * FROM products ORDER BY created_at DESC";
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                products.add(new ProductInfo(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("description"),
                        rs.getDouble("price"),
                        rs.getString("currency"),
                        rs.getString("action_type"),
                        rs.getString("action_config"),
                        rs.getObject("plugin_id") != null ? rs.getInt("plugin_id") : null,
                        rs.getString("file_path"),
                        rs.getString("file_name"),
                        rs.getBoolean("is_active"),
                        rs.getTimestamp("created_at")));
            }
        }
        return products;
    }

    public List<ProductInfo> getActiveProducts() throws SQLException {
        List<ProductInfo> products = new ArrayList<>();
        String sql = "SELECT * FROM products WHERE is_active = TRUE ORDER BY created_at DESC";
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                products.add(new ProductInfo(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("description"),
                        rs.getDouble("price"),
                        rs.getString("currency"),
                        rs.getString("action_type"),
                        rs.getString("action_config"),
                        rs.getObject("plugin_id") != null ? rs.getInt("plugin_id") : null,
                        rs.getString("file_path"),
                        rs.getString("file_name"),
                        rs.getBoolean("is_active"),
                        rs.getTimestamp("created_at")));
            }
        }
        return products;
    }

    public ProductInfo getProduct(int productId) throws SQLException {
        String sql = "SELECT * FROM products WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, productId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new ProductInfo(
                            rs.getInt("id"),
                            rs.getString("name"),
                            rs.getString("description"),
                            rs.getDouble("price"),
                            rs.getString("currency"),
                            rs.getString("action_type"),
                            rs.getString("action_config"),
                            rs.getObject("plugin_id") != null ? rs.getInt("plugin_id") : null,
                            rs.getString("file_path"),
                            rs.getString("file_name"),
                            rs.getBoolean("is_active"),
                            rs.getTimestamp("created_at"));
                }
            }
        }
        return null;
    }

    // ==================== ORDER METHODS ====================

    public int createOrder(int userId, int productId, String paymentProvider, double amount, String currency)
            throws SQLException {
        String sql = "INSERT INTO orders (user_id, product_id, payment_provider, amount, currency) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, userId);
            stmt.setInt(2, productId);
            stmt.setString(3, paymentProvider);
            stmt.setDouble(4, amount);
            stmt.setString(5, currency);
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return -1;
    }

    public void updateOrderStatus(int orderId, String status, String paymentProviderId) throws SQLException {
        String sql = "UPDATE orders SET status = ?, payment_provider_id = ?, completed_at = CASE WHEN ? = 'COMPLETED' THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, status);
            stmt.setString(2, paymentProviderId);
            stmt.setString(3, status);
            stmt.setInt(4, orderId);
            stmt.executeUpdate();
        }
    }

    public boolean orderExistsByProviderId(String paymentProviderId) throws SQLException {
        String sql = "SELECT 1 FROM orders WHERE payment_provider_id = ? AND status = 'COMPLETED'";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, paymentProviderId);
            return stmt.executeQuery().next();
        }
    }

    public OrderInfo getOrderByProviderId(String paymentProviderId) throws SQLException {
        String sql = "SELECT * FROM orders WHERE payment_provider_id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, paymentProviderId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new OrderInfo(
                            rs.getInt("id"),
                            rs.getInt("user_id"),
                            rs.getInt("product_id"),
                            rs.getString("payment_provider"),
                            rs.getString("payment_provider_id"),
                            rs.getDouble("amount"),
                            rs.getString("currency"),
                            rs.getString("status"),
                            rs.getTimestamp("created_at"),
                            rs.getTimestamp("completed_at"));
                }
            }
        }
        return null;
    }

    public List<OrderInfo> getAllOrders() throws SQLException {
        List<OrderInfo> orders = new ArrayList<>();
        String sql = "SELECT * FROM orders ORDER BY created_at DESC";
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                orders.add(new OrderInfo(
                        rs.getInt("id"),
                        rs.getInt("user_id"),
                        rs.getInt("product_id"),
                        rs.getString("payment_provider"),
                        rs.getString("payment_provider_id"),
                        rs.getDouble("amount"),
                        rs.getString("currency"),
                        rs.getString("status"),
                        rs.getTimestamp("created_at"),
                        rs.getTimestamp("completed_at")));
            }
        }
        return orders;
    }

    public List<OrderInfo> getOrdersForUser(int userId) throws SQLException {
        List<OrderInfo> orders = new ArrayList<>();
        String sql = "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    orders.add(new OrderInfo(
                            rs.getInt("id"),
                            rs.getInt("user_id"),
                            rs.getInt("product_id"),
                            rs.getString("payment_provider"),
                            rs.getString("payment_provider_id"),
                            rs.getDouble("amount"),
                            rs.getString("currency"),
                            rs.getString("status"),
                            rs.getTimestamp("created_at"),
                            rs.getTimestamp("completed_at")));
                }
            }
        }
        return orders;
    }

    // ==================== PAYMENT SETTINGS ====================

    // AES key derived from passphrase via SHA-256
    // SECURITY: Set the BARRON_ENCRYPTION_KEY environment variable in production.
    // The default value is only for development/testing purposes.
    private static final String ENCRYPTION_PASSPHRASE = System.getenv("BARRON_ENCRYPTION_KEY") != null
            ? System.getenv("BARRON_ENCRYPTION_KEY")
            : "BarronSecureKey!";

    private javax.crypto.SecretKey getEncryptionKey() {
        try {
            byte[] keyBytes = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(ENCRYPTION_PASSPHRASE.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive encryption key", e);
        }
    }

    private String encrypt(String value) {
        if (value == null || value.isEmpty())
            return null;
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12]; // GCM recommended IV size
            new java.security.SecureRandom().nextBytes(iv);
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, getEncryptionKey(), gcmSpec);
            byte[] encrypted = cipher.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // Prepend IV to ciphertext
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            System.err.println("[ENCRYPTION ERROR] " + e.getMessage());
            return null;
        }
    }

    private String decrypt(String value) {
        if (value == null || value.isEmpty())
            return null;
        try {
            byte[] combined = Base64.getDecoder().decode(value);
            byte[] iv = new byte[12];
            byte[] encrypted = new byte[combined.length - 12];
            System.arraycopy(combined, 0, iv, 0, 12);
            System.arraycopy(combined, 12, encrypted, 0, encrypted.length);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, getEncryptionKey(), gcmSpec);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Fallback: try legacy XOR decryption for migration
            try {
                byte[] legacyEncrypted = Base64.getDecoder().decode(value);
                byte[] key = ENCRYPTION_PASSPHRASE.getBytes();
                byte[] legacyDecrypted = new byte[legacyEncrypted.length];
                for (int i = 0; i < legacyEncrypted.length; i++) {
                    legacyDecrypted[i] = (byte) (legacyEncrypted[i] ^ key[i % key.length]);
                }
                return new String(legacyDecrypted);
            } catch (Exception e2) {
                System.err.println("[DECRYPTION ERROR] " + e.getMessage());
                return null;
            }
        }
    }

    // Legacy payment methods removed to resolve conflict with new implementation

    // ==================== AUDIT LOG ====================

    public void logAdminAction(int adminId, String action, String targetType, Integer targetId,
            String details, String ipAddress) throws SQLException {
        String sql = "INSERT INTO admin_logs (admin_id, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            stmt.setString(2, action);
            stmt.setString(3, targetType);
            if (targetId != null) {
                stmt.setInt(4, targetId);
            } else {
                stmt.setNull(4, Types.INTEGER);
            }
            stmt.setString(5, details);
            stmt.setString(6, ipAddress);
            stmt.executeUpdate();
        }
    }

    public List<AdminLogInfo> getAdminLogs(int limit) throws SQLException {
        List<AdminLogInfo> logs = new ArrayList<>();
        String sql = """
                SELECT al.*, u.username as admin_username
                FROM admin_logs al
                LEFT JOIN users u ON al.admin_id = u.id
                ORDER BY al.created_at DESC
                LIMIT ?
                """;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, limit);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    logs.add(new AdminLogInfo(
                            rs.getInt("id"),
                            rs.getInt("admin_id"),
                            rs.getString("admin_username"),
                            rs.getString("action"),
                            rs.getString("target_type"),
                            rs.getObject("target_id") != null ? rs.getInt("target_id") : null,
                            rs.getString("details"),
                            rs.getString("ip_address"),
                            rs.getTimestamp("created_at")));
                }
            }
        }
        return logs;
    }

    // ==================== PASSWORD RESET ====================

    public String createPasswordResetToken(String email) throws SQLException {
        // First check if user exists
        String userSql = "SELECT id FROM users WHERE email = ?";
        int userId = -1;
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(userSql)) {
            stmt.setString(1, email);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    userId = rs.getInt("id");
                } else {
                    return null; // User not found
                }
            }
        }

        // 1. Passive Cleanup: Delete ALL expired tokens
        String cleanupSql = "DELETE FROM password_resets WHERE expires_at < NOW()";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(cleanupSql)) {
            stmt.executeUpdate();
        }

        // 2. User Cleanup: Delete existing valid tokens for this user (Single-use
        // enforcement)
        String userCleanupSql = "DELETE FROM password_resets WHERE user_id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(userCleanupSql)) {
            stmt.setInt(1, userId);
            stmt.executeUpdate();
        }

        // 3. Create new token (10 minutes validity)
        String token = UUID.randomUUID().toString().replace("-", "");
        String sql = "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setString(2, token);
            stmt.executeUpdate();
        }

        return token;
    }

    public Integer validateResetToken(String token) throws SQLException {
        // Read-Only validation for performance
        String sql = "SELECT user_id FROM password_resets WHERE token = ? AND expires_at > NOW()";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, token);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("user_id");
                }
            }
        }
        return null;
    }

    public boolean resetPassword(String token, String newPassword) throws SQLException {
        Integer userId = validateResetToken(token);
        if (userId == null)
            return false;

        // Update password
        String passwordHash = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        String updateSql = "UPDATE users SET password_hash = ? WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(updateSql)) {
            stmt.setString(1, passwordHash);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }

        // Delete used token to prevent replay functionality
        String deleteSql = "DELETE FROM password_resets WHERE token = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(deleteSql)) {
            stmt.setString(1, token);
            stmt.executeUpdate();
        }

        return true;
    }

    // ==================== SMTP SETTINGS ====================

    public record SmtpConfig(String host, int port, String security, String user, String pass, String fromEmail,
            boolean isEnabled) {
        public String host() {
            return host;
        }

        public int port() {
            return port;
        }

        public String security() {
            return security;
        }

        public String user() {
            return user;
        }

        public String pass() {
            return pass;
        }

        public String fromEmail() {
            return fromEmail;
        }

        public boolean isEnabled() {
            return isEnabled;
        }
    }

    public void saveSmtpSettings(String host, int port, String security, String user, String pass, String fromEmail,
            boolean isEnabled)
            throws SQLException {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("""
                        CREATE TABLE IF NOT EXISTS smtp_settings (
                            id INT PRIMARY KEY DEFAULT 1,
                            host VARCHAR(255),
                            port INT,
                            security VARCHAR(20) DEFAULT 'SSL',
                            username VARCHAR(255),
                            password VARCHAR(255),
                            from_email VARCHAR(255),
                            is_enabled BOOLEAN DEFAULT FALSE
                        )
                    """);
            // Add security column if not exists (for migration)
            try {
                stmt.execute("ALTER TABLE smtp_settings ADD COLUMN security VARCHAR(20) DEFAULT 'SSL'");
            } catch (SQLException e) {
                // Column already exists, ignore
            }
        }

        String sql = "INSERT INTO smtp_settings (id, host, port, security, username, password, from_email, is_enabled) VALUES (1, ?, ?, ?, ?, ?, ?, ?) "
                +
                "ON DUPLICATE KEY UPDATE host=?, port=?, security=?, username=?, password=?, from_email=?, is_enabled=?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setInt(2, port);
            stmt.setString(3, security);
            stmt.setString(4, user);
            stmt.setString(5, pass);
            stmt.setString(6, fromEmail);
            stmt.setBoolean(7, isEnabled);

            stmt.setString(8, host);
            stmt.setInt(9, port);
            stmt.setString(10, security);
            stmt.setString(11, user);
            stmt.setString(12, pass);
            stmt.setString(13, fromEmail);
            stmt.setBoolean(14, isEnabled);
            stmt.executeUpdate();
        }
    }

    public SmtpConfig getSmtpSettings() {
        try {
            ensureConnection();
            try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
                stmt.execute("""
                            CREATE TABLE IF NOT EXISTS smtp_settings (
                                id INT PRIMARY KEY DEFAULT 1,
                                host VARCHAR(255),
                                port INT,
                                security VARCHAR(20) DEFAULT 'SSL',
                                username VARCHAR(255),
                                password VARCHAR(255),
                                from_email VARCHAR(255),
                                is_enabled BOOLEAN DEFAULT FALSE
                            )
                        """);
                // Add security column if not exists (for migration)
                try {
                    stmt.execute("ALTER TABLE smtp_settings ADD COLUMN security VARCHAR(20) DEFAULT 'SSL'");
                } catch (SQLException e) {
                    // Column already exists, ignore
                }
            }

            try (Connection conn = getConnection();
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT * FROM smtp_settings WHERE id = 1")) {
                if (rs.next()) {
                    String security = "SSL";
                    try {
                        security = rs.getString("security");
                        if (security == null || security.isEmpty())
                            security = "SSL";
                    } catch (SQLException e) {
                        // Column doesn't exist yet
                    }
                    return new SmtpConfig(
                            rs.getString("host"),
                            rs.getInt("port"),
                            security,
                            rs.getString("username"),
                            rs.getString("password"),
                            rs.getString("from_email"),
                            rs.getBoolean("is_enabled"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new SmtpConfig("", 587, "SSL", "", "", "", false);
    }
    // ==================== PAYMENT SETTINGS ====================

    public void savePaymentSettings(String provider, String apiKey, String apiSecret, String webhookSecret,
            String merchantId, boolean isEnabled, boolean isTestMode) {
        String sql = "UPDATE payment_settings SET provider=?, api_key=?, api_secret=?, webhook_secret=?, merchant_id=?, is_enabled=?, is_test_mode=? WHERE id=1";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, provider);
            stmt.setString(2, apiKey);
            stmt.setString(3, apiSecret);
            stmt.setString(4, webhookSecret);
            stmt.setString(5, merchantId);
            stmt.setBoolean(6, isEnabled);
            stmt.setBoolean(7, isTestMode);
            stmt.executeUpdate();
            replicateToSecondary(sql, provider, apiKey, apiSecret, webhookSecret, merchantId, isEnabled, isTestMode);
            System.out.println("[DB] Payment settings saved.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Payment visibility record
    public record PaymentConfig(String provider, String apiKey, String apiSecret,
            String webhookSecret, String merchantId, boolean isEnabled, boolean isTestMode,
            boolean stripeActive, boolean paytrActive, boolean shopierActive) {
        public String provider() {
            return provider;
        }

        public String apiKey() {
            return apiKey;
        }

        public String apiSecret() {
            return apiSecret;
        }

        public String webhookSecret() {
            return webhookSecret;
        }

        public String merchantId() {
            return merchantId;
        }

        public boolean isEnabled() {
            return isEnabled;
        }

        public boolean isTestMode() {
            return isTestMode;
        }

        public boolean stripeActive() {
            return stripeActive;
        }

        public boolean paytrActive() {
            return paytrActive;
        }

        public boolean shopierActive() {
            return shopierActive;
        }
    }

    public PaymentConfig getPaymentSettings() {
        String sql = "SELECT * FROM payment_settings WHERE id=1";
        try (Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return new PaymentConfig(
                        rs.getString("provider"),
                        rs.getString("api_key"),
                        rs.getString("api_secret"),
                        rs.getString("webhook_secret"),
                        rs.getString("merchant_id"),
                        rs.getBoolean("is_enabled"),
                        rs.getBoolean("is_test_mode"),
                        rs.getBoolean("stripe_active"),
                        rs.getBoolean("paytr_active"),
                        rs.getBoolean("shopier_active"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new PaymentConfig("STRIPE", "", "", "", "", false, true, false, false, false);
    }

    public void savePaymentVisibility(boolean stripeActive, boolean paytrActive, boolean shopierActive) {
        String sql = "UPDATE payment_settings SET stripe_active=?, paytr_active=?, shopier_active=? WHERE id=1";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setBoolean(1, stripeActive);
            stmt.setBoolean(2, paytrActive);
            stmt.setBoolean(3, shopierActive);
            stmt.executeUpdate();
            replicateToSecondary(sql, stripeActive, paytrActive, shopierActive);
            System.out.println("[DB] Payment visibility saved.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ==================== SITE SETTINGS (Footer Links) ====================

    public record FooterLinks(String discord, String spigot, String builtbybit) {
        public String discord() {
            return discord;
        }

        public String spigot() {
            return spigot;
        }

        public String builtbybit() {
            return builtbybit;
        }
    }

    public FooterLinks getFooterLinks() throws SQLException {
        String discord = getSetting("footer_discord");
        String spigot = getSetting("footer_spigot");
        String builtbybit = getSetting("footer_builtbybit");
        return new FooterLinks(discord, spigot, builtbybit);
    }

    public void setFooterLinks(String discord, String spigot, String builtbybit) throws SQLException {
        setSetting("footer_discord", discord);
        setSetting("footer_spigot", spigot);
        setSetting("footer_builtbybit", builtbybit);
    }

    private String getSetting(String key) throws SQLException {
        String sql = "SELECT setting_value FROM site_settings WHERE setting_key = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, key);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("setting_value");
            }
        }
        return "";
    }

    private void setSetting(String key, String value) throws SQLException {
        String sql = "INSERT INTO site_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.setString(2, value != null ? value : "");
            stmt.setString(3, value != null ? value : "");
            stmt.executeUpdate();
        }
        replicateToSecondary(sql, key, value, value);
    }

}
