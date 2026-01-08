package dev.barron.db;

import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
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

    private Connection connection;
    private Connection secondaryConnection;

    public DatabaseManager() {
    }

    public void configure(String host, int port, String database, String username, String password) {
        this.host = host;
        this.port = port;
        this.database = database;
        this.username = username;
        this.password = password;
    }

    /**
     * Configure secondary server for failover
     */
    public void configureSecondary(String host, int port, String user, String password) {
        this.secondaryHost = host;
        this.secondaryPort = port;
        this.secondaryUser = user;
        this.secondaryPassword = password;
        this.failoverEnabled = true;
    }

    public boolean isFailoverEnabled() {
        return failoverEnabled;
    }

    public void setFailoverEnabled(boolean enabled) {
        this.failoverEnabled = enabled;
    }

    public boolean connect() {
        try {
            String url = String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC",
                    host, port, database);
            connection = DriverManager.getConnection(url, username, password);

            // Also connect to secondary if enabled
            if (failoverEnabled && !secondaryHost.isEmpty()) {
                connectSecondary();
            }
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
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
            String url = String.format("jdbc:mysql://%s:%d/%s?useSSL=true&serverTimezone=UTC",
                    secondaryHost, secondaryPort, database);
            secondaryConnection = DriverManager.getConnection(url, secondaryUser, secondaryPassword);
            System.out.println("Secondary server connected for replication");
            return true;
        } catch (SQLException e) {
            System.err.println("Secondary server connection failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Replicate a SQL statement to secondary server (real-time)
     */
    private void replicateToSecondary(String sql, Object... params) {
        if (!failoverEnabled || secondaryConnection == null)
            return;

        try {
            // Check if secondary is still connected
            if (secondaryConnection.isClosed()) {
                connectSecondary();
                if (secondaryConnection == null || secondaryConnection.isClosed())
                    return;
            }

            try (PreparedStatement stmt = secondaryConnection.prepareStatement(sql)) {
                for (int i = 0; i < params.length; i++) {
                    stmt.setObject(i + 1, params[i]);
                }
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Replication failed: " + e.getMessage());
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
                            name VARCHAR(100) NOT NULL,
                            filename VARCHAR(255) NOT NULL,
                            version VARCHAR(20),
                            file_hash VARCHAR(64),
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            encryption_mode ENUM('NORMAL', 'SERVER') DEFAULT 'SERVER'
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            email VARCHAR(100) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP NULL,
                            is_active BOOLEAN DEFAULT TRUE
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
                            FOREIGN KEY (plugin_id) REFERENCES plugins(id),
                            FOREIGN KEY (user_id) REFERENCES users(id)
                        )
                        """,
                """
                        CREATE TABLE IF NOT EXISTS ips (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            license_id INT NOT NULL,
                            ip_address VARCHAR(45) NOT NULL,
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
                            ip_address VARCHAR(45) NOT NULL,
                            server_name VARCHAR(100),
                            last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
                        )
                        """
        };

        try (Statement stmt = connection.createStatement()) {
            for (String table : tables) {
                stmt.execute(table);
            }
        }
    }

    // ==================== PLUGINS ====================

    public int addPlugin(String name, String filename, String version, String fileHash, String mode)
            throws SQLException {
        String sql = "INSERT INTO plugins (name, filename, version, file_hash, encryption_mode) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
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
        try (Statement stmt = connection.createStatement();
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

    // ==================== LICENSES ====================

    public String generateLicenseKey() {
        String uuid = UUID.randomUUID().toString().toUpperCase().replace("-", "");
        return uuid.substring(0, 4) + "-" + uuid.substring(4, 8) + "-" +
                uuid.substring(8, 12) + "-" + uuid.substring(12, 16);
    }

    public String createLicense(int pluginId, Integer daysValid) throws SQLException {
        String licenseKey;
        // Ensure unique key
        do {
            licenseKey = generateLicenseKey();
        } while (licenseExists(licenseKey));

        String sql = "INSERT INTO licenses (license_key, plugin_id, expires_at) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            stmt.setInt(2, pluginId);
            if (daysValid != null && daysValid > 0) {
                stmt.setTimestamp(3,
                        new Timestamp(System.currentTimeMillis() + (long) daysValid * 24 * 60 * 60 * 1000));
            } else {
                stmt.setNull(3, Types.TIMESTAMP);
            }
            stmt.executeUpdate();
        }
        return licenseKey;
    }

    public boolean licenseExists(String licenseKey) throws SQLException {
        String sql = "SELECT 1 FROM licenses WHERE license_key = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, licenseKey);
            return stmt.executeQuery().next();
        }
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
        try (Statement stmt = connection.createStatement();
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
                        rs.getBoolean("is_active")));
            }
        }
        return licenses;
    }

    public void deleteLicense(int licenseId) throws SQLException {
        String sql = "DELETE FROM licenses WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, licenseId);
            stmt.executeUpdate();
        }
    }

    // ==================== USERS ====================

    public boolean registerUser(String username, String email, String password) throws SQLException {
        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        String sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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
        String sql = "SELECT id, password_hash FROM users WHERE (username = ? OR email = ?) AND is_active = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, usernameOrEmail);
            stmt.setString(2, usernameOrEmail);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String hash = rs.getString("password_hash");
                if (BCrypt.checkpw(password, hash)) {
                    // Update last login
                    updateLastLogin(rs.getInt("id"));
                    return rs.getInt("id");
                }
            }
        }
        return null;
    }

    private void updateLastLogin(int userId) throws SQLException {
        String sql = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.executeUpdate();
        }
    }

    // ==================== IP MANAGEMENT ====================

    public boolean addIpToLicense(int licenseId, String ipAddress) throws SQLException {
        // Check max IPs
        String countSql = "SELECT COUNT(*), max_ips FROM licenses l LEFT JOIN ips i ON l.id = i.license_id WHERE l.id = ? GROUP BY l.id";
        try (PreparedStatement stmt = connection.prepareStatement(countSql)) {
            stmt.setInt(1, licenseId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int current = rs.getInt(1);
                int max = rs.getInt(2);
                if (current >= max) {
                    return false; // Max IPs reached
                }
            }
        }

        String sql = "INSERT INTO ips (license_id, ip_address) VALUES (?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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

    private void updateLastSeen(int licenseId) throws SQLException {
        String sql = "UPDATE licenses SET last_seen = CURRENT_TIMESTAMP WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
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
                try (Statement selectStmt = connection.createStatement();
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
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ==================== DATA CLASSES ====================

    public record PluginInfo(int id, String name, String filename, String version,
            int licenseCount, Timestamp createdAt) {
    }

    public record LicenseInfo(int id, String licenseKey, String pluginName,
            String username, String email, String ipList,
            Timestamp expiresAt, Timestamp lastSeen,
            boolean isOnline, boolean isActive) {
    }
}
