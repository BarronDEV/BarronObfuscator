package dev.barron.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import dev.barron.db.DatabaseManager;
import dev.barron.gui.MainWindow;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.Gson;

import javax.net.ssl.*;
import java.net.URLDecoder;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// import javax.mail.*;
// import javax.mail.internet.*;
import dev.barron.utils.TotpUtil;

public class LicenseServer {

    private static HttpServer apiServer;
    private static HttpServer webServer;
    private static DatabaseManager db;
    private static int apiPort = 8000;
    private static int webPort = 8080;
    private static final Gson gson = new Gson();
    // Session Storage: Token -> UserId
    private static final Map<String, Integer> sessions = new ConcurrentHashMap<>();

    // Rate Limiting
    private static final Map<String, List<Long>> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long RATE_LIMIT_WINDOW = 60_000; // 1 minute in ms

    // Password Reset Rate Limits
    private static final int RESET_RATE_LIMIT_MAX = 15;
    private static final long RESET_RATE_LIMIT_WINDOW = 3600000L; // 1 hour

    // SSL Configuration
    private static boolean sslEnabled = false;
    private static String sslCertPath = "";
    private static String sslKeyPath = "";

    // Server domain for email links (e.g., "panel.example.com")
    private static String serverDomain = "";

    // Login Throttling: IP -> Failed attempts with timestamps
    private static final Map<String, LoginAttemptInfo> loginAttempts = new ConcurrentHashMap<>();
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOGIN_LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in ms

    // Login attempt tracking class
    static class LoginAttemptInfo {
        int failedAttempts = 0;
        long lastAttemptTime = 0;
        long lockoutUntil = 0;

        void recordFailure() {
            failedAttempts++;
            lastAttemptTime = System.currentTimeMillis();
            if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
                lockoutUntil = System.currentTimeMillis() + LOGIN_LOCKOUT_DURATION;
            }
        }

        void reset() {
            failedAttempts = 0;
            lockoutUntil = 0;
        }

        boolean isLockedOut() {
            if (lockoutUntil > 0 && System.currentTimeMillis() < lockoutUntil) {
                return true;
            }
            // Reset if lockout expired
            if (lockoutUntil > 0 && System.currentTimeMillis() >= lockoutUntil) {
                reset();
            }
            return false;
        }

        long getRemainingLockoutSeconds() {
            return Math.max(0, (lockoutUntil - System.currentTimeMillis()) / 1000);
        }
    }

    // Set server domain for email links (called from MainWindow)
    public static void setServerDomain(String domain) {
        serverDomain = domain != null ? domain : "";
    }

    // Legacy start method (no SSL)
    public static void start(DatabaseManager databaseManager, int serverPort, int webPanelPort) {
        start(databaseManager, serverPort, webPanelPort, false, null, null);
    }

    // New start method with SSL support
    public static void start(DatabaseManager databaseManager, int serverPort, int webPanelPort,
            boolean enableSsl, String certPath, String keyPath) {
        db = databaseManager;
        apiPort = serverPort;
        webPort = webPanelPort;
        sslEnabled = enableSsl;
        sslCertPath = certPath;
        sslKeyPath = keyPath;

        try {
            // Stop existing if running
            stop();

            SSLContext sslContext = null;
            if (sslEnabled && sslCertPath != null && !sslCertPath.isEmpty()
                    && sslKeyPath != null && !sslKeyPath.isEmpty()) {
                try {
                    sslContext = createSSLContext(sslCertPath, sslKeyPath);
                } catch (Exception e) {
                    System.err.println("[LicenseServer] Failed to create SSL context: " + e.getMessage());
                    System.err.println("[LicenseServer] Falling back to HTTP");
                    e.printStackTrace();
                }
            }

            // 1. API Server (Validation)
            if (sslContext != null) {
                HttpsServer httpsApiServer = HttpsServer.create(new InetSocketAddress(apiPort), 0);
                httpsApiServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
                apiServer = httpsApiServer;
                System.out.println("[LicenseServer] API Listening on HTTPS port " + apiPort);
            } else {
                apiServer = HttpServer.create(new InetSocketAddress(apiPort), 0);
                System.out.println("[LicenseServer] API Listening on HTTP port " + apiPort);
            }
            apiServer.createContext("/api/verify", new VerifyHandler());
            apiServer.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            apiServer.start();

            // 2. Web Panel Server
            if (sslContext != null) {
                HttpsServer httpsWebServer = HttpsServer.create(new InetSocketAddress(webPort), 0);
                httpsWebServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
                webServer = httpsWebServer;
                System.out.println("[LicenseServer] Web Panel Listening on HTTPS port " + webPort);
            } else {
                webServer = HttpServer.create(new InetSocketAddress(webPort), 0);
                System.out.println("[LicenseServer] Web Panel Listening on HTTP port " + webPort);
            }

            // Auth
            webServer.createContext("/api/auth/login", new LoginHandler());
            webServer.createContext("/api/auth/register", new RegisterHandler());
            webServer.createContext("/api/auth/logout", new LogoutHandler());
            webServer.createContext("/api/auth/forgot-password", new ForgotPasswordHandler());
            webServer.createContext("/api/auth/reset-password", new ResetPasswordHandler());
            webServer.createContext("/api/auth/2fa", new TwoFactorHandler());

            // User Dashboard
            webServer.createContext("/api/user", new UserDashboardHandler()); // Handles profile, licenses

            // Products (public)
            webServer.createContext("/api/products", new ProductHandler());

            // Admin Panel (protected)
            webServer.createContext("/api/admin", new AdminHandler());

            // Public Settings (footer links, etc.)
            webServer.createContext("/api/settings", new SettingsHandler());

            // Payments
            webServer.createContext("/api/payment", new PaymentHandler());

            // Static file handler for SPA
            webServer.createContext("/", new StaticFileHandler());

            webServer.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            webServer.start();
            System.out.println("[LicenseServer] Web Panel Listening on port " + webPort);

        } catch (IOException e) {
            System.err.println("[LicenseServer] Failed to start servers: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void stop() {
        if (apiServer != null) {
            apiServer.stop(0);
        }
        if (webServer != null) {
            webServer.stop(0);
        }
        System.out.println("[LicenseServer] Stopped.");
    }

    /**
     * Create SSLContext from PEM certificate and key files (Cloudflare Origin
     * Certificate format)
     */
    private static SSLContext createSSLContext(String certPath, String keyPath) throws Exception {
        // Read certificate
        String certPem = Files.readString(Path.of(certPath));
        String keyPem = Files.readString(Path.of(keyPath));

        // Parse certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        String certContent = certPem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] certBytes = Base64.getDecoder().decode(certContent);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

        // Parse private key (supports both PKCS#8 and RSA formats)
        String keyContent = keyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);

        PrivateKey privateKey;
        try {
            // Try PKCS#8 format first
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(keySpec);
        } catch (Exception e) {
            // Fallback for legacy RSA format - may need conversion
            throw new Exception("Failed to parse private key. Please ensure it's in PKCS#8 format. " +
                    "Use: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem");
        }

        // Create KeyStore
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server", privateKey, "changeit".toCharArray(), new java.security.cert.Certificate[] { cert });

        // Create KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "changeit".toCharArray());

        // Create TrustManager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Create SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        System.out.println("[LicenseServer] SSL Context created successfully");
        return sslContext;
    }

    // Secret for signing session tokens (Shared with Obfuscator client logic)
    // Dynamic Secret: Loaded from MainWindow settings at runtime
    private static String TOKEN_SECRET = "BarronSuperSecretKey2026_DEFAULT";

    // Set dynamic secret from GUI
    public static void setTokenSecret(String secret) {
        if (secret != null && !secret.isEmpty()) {
            TOKEN_SECRET = secret;
            System.out.println("[LicenseServer] Session Token Secret updated.");
        }
    }

    /**
     * Generate a cryptographic session token
     * Token = HMAC-SHA256(licenseKey + timestamp, SECRET)
     */
    private static String generateSessionToken(String key, long timestamp) {
        try {
            String data = key + ":" + timestamp;
            javax.crypto.Mac sha256_HMAC = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secret_key = new javax.crypto.spec.SecretKeySpec(
                    TOKEN_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            byte[] hash = sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            e.printStackTrace();
            return UUID.randomUUID().toString(); // Fail-safe fallback
        }
    }

    /**
     * Rate limiting: Check if IP has exceeded request limit
     * Returns true if request is allowed, false if rate limited
     */
    private static synchronized boolean checkRateLimit(String ip) {
        long now = System.currentTimeMillis();

        // Get or create request timestamps list for this IP
        java.util.List<Long> timestamps = requestCounts.computeIfAbsent(ip, k -> new ArrayList<>());

        // Remove timestamps outside the time window
        timestamps.removeIf(t -> (now - t) > RATE_LIMIT_WINDOW);

        // Check if limit exceeded
        if (timestamps.size() >= MAX_REQUESTS_PER_MINUTE) {
            System.out.println("[RATE LIMIT] Blocked request from: " + ip);
            return false;
        }

        // Add current request timestamp
        timestamps.add(now);
        return true;
    }

    static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();

            // Cloudflare Support
            if (exchange.getRequestHeaders().containsKey("Cf-connecting-ip")) {
                clientIp = exchange.getRequestHeaders().get("Cf-connecting-ip").get(0);
            } else if (exchange.getRequestHeaders().containsKey("CF-Connecting-IP")) {
                clientIp = exchange.getRequestHeaders().get("CF-Connecting-IP").get(0);
            } else if (exchange.getRequestHeaders().containsKey("X-Forwarded-For")) {
                clientIp = exchange.getRequestHeaders().get("X-Forwarded-For").get(0).split(",")[0].trim();
            }

            String method = exchange.getRequestMethod();

            // Rate limiting check
            if (!checkRateLimit(clientIp)) {
                System.out.println("[VerifyHandler] Rate limit exceeded for " + clientIp);
                sendResponse(exchange, 429, errorJson("Too many requests. Try again later."));
                return;
            }

            if (!"GET".equals(method) && !"POST".equals(method)) {
                System.out.println("[VerifyHandler] Invalid method: " + method);
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            // 1. Try to get params from URL Query
            Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
            String key = params.get("key");
            String hwid = params.get("hwid");

            // 2. If POST, try reading JSON body
            if ("POST".equals(method)) {
                try {
                    String body = getRequestBody(exchange);

                    if (body != null && !body.isEmpty()) {
                        // If query key is missing, try JSON
                        if (key == null || key.isEmpty()) {
                            try {
                                JsonObject json = gson.fromJson(body, JsonObject.class);
                                if (json.has("key")) {
                                    key = json.get("key").getAsString();
                                }
                                if (json.has("hwid")) {
                                    hwid = json.get("hwid").getAsString();
                                }
                            } catch (Exception e) {
                                System.out.println("[VerifyHandler] Failed to parse JSON body: " + e.getMessage());
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[VerifyHandler] Body Read Error: " + e.getMessage());
                }
            }

            // Basic IP detection if hwid not provided (fallback)
            if (hwid == null || hwid.isEmpty()) {
                hwid = clientIp;
            }

            if (key == null || key.isEmpty()) {
                System.out.println("[VerifyHandler] Missing license key!");
                sendResponse(exchange, 400, errorJson("Missing license key"));
                return;
            }

            try {
                // Ensure connection is proper
                if (!db.testConnection()) {
                    db.connect();
                }

                // LICENSE HOARDING DETECTION: Track unique IPs per license
                int uniqueIpCount = db.trackLicenseIpAccess(key, hwid);
                boolean isSuspicious = uniqueIpCount > 3; // 3+ unique IPs = suspicious

                boolean valid = db.tryAuthLicense(key, hwid);

                System.out.println("[VerifyHandler] Key Valid: " + valid + ", Suspicious: " + isSuspicious);

                JsonObject response = new JsonObject();
                response.addProperty("valid", valid && !isSuspicious);
                response.addProperty("timestamp", System.currentTimeMillis());

                if (isSuspicious) {
                    response.addProperty("message", "License suspended: Unusual activity detected");
                    response.addProperty("suspended", true);
                    System.out.println(
                            "[LICENSE ABUSE] Key " + key.substring(0, Math.min(8, key.length())) + "... accessed from "
                                    + uniqueIpCount + " unique IPs");
                } else if (valid) {
                    response.addProperty("message", "License valid");
                    // Update heartbeat/session info
                    db.updateHeartbeat(key, hwid, "Remote-Server");

                    // NEW: Generate Session Token for Kill Switch
                    // This token is a signature of the key + timestamp using our secret
                    String sessionToken = generateSessionToken(key, response.get("timestamp").getAsLong());
                    response.addProperty("sessionToken", sessionToken);
                } else {
                    response.addProperty("message", "Invalid license or IP");
                }

                String jsonResponse = gson.toJson(response);
                sendResponse(exchange, 200, jsonResponse);

            } catch (SQLException e) {
                // ERROR MASKING: Log details server-side only
                System.err.println("[VERIFY ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Verification service temporarily unavailable. Code: VER-500"));
            }
        }
    }

    // ==================== AUTH HANDLERS ====================

    // Helper for CORS
    private static void enableCORS(HttpExchange exchange) {
        String origin = serverDomain != null && !serverDomain.isEmpty() ? serverDomain : "*";
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", origin);
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange); // Enable CORS

            String clientIp = getClientIp(exchange);
            String method = exchange.getRequestMethod();
            System.out.println("[LoginHandler] Request from " + clientIp + ", Method: " + method);

            if ("OPTIONS".equalsIgnoreCase(method)) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"POST".equals(method)) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            // Check if IP is locked out
            LoginAttemptInfo attemptInfo = loginAttempts.computeIfAbsent(clientIp, k -> new LoginAttemptInfo());
            if (attemptInfo.isLockedOut()) {
                long remaining = attemptInfo.getRemainingLockoutSeconds();
                System.out.println("[LoginHandler] IP Locked out: " + clientIp);
                sendResponse(exchange, 429,
                        errorJson("Too many failed attempts. Try again in " + remaining + " seconds"));
                return;
            }

            try {
                String body = getRequestBody(exchange);

                JsonObject json = gson.fromJson(body, JsonObject.class);
                String user = json.has("username") ? json.get("username").getAsString() : "";
                String pass = json.has("password") ? json.get("password").getAsString() : "";
                // New: 2FA Code
                String code = json.has("code") ? json.get("code").getAsString() : null;

                if (!db.testConnection())
                    db.connect();

                Integer userId = db.authenticateUser(user, pass);

                if (userId != null) {
                    attemptInfo.reset();

                    // 2FA Check
                    var userInfo = db.getUser(userId);
                    if (userInfo != null && userInfo.twoFactorEnabled()) {
                        if (code == null || code.isEmpty()) {
                            // Prompt for 2FA
                            JsonObject resp = new JsonObject();
                            resp.addProperty("success", false);
                            resp.addProperty("require2fa", true);
                            resp.addProperty("message", "2FA Code Required");
                            sendResponse(exchange, 200, gson.toJson(resp));
                            return;
                        } else {
                            // Verify Code
                            try {
                                if (!TotpUtil.verifyCode(userInfo.twoFactorSecret(), Integer.parseInt(code))) {
                                    attemptInfo.recordFailure();
                                    sendResponse(exchange, 401, errorJson("Invalid 2FA Code"));
                                    return;
                                }
                            } catch (NumberFormatException e) {
                                attemptInfo.recordFailure();
                                sendResponse(exchange, 400, errorJson("Invalid 2FA Code format"));
                                return;
                            }
                        }
                    }

                    // Session Fixation Protection
                    // Generate new Session ID
                    String token = UUID.randomUUID().toString();
                    sessions.put(token, userId);

                    // Cookies
                    String cookie = "session_token=" + token + "; HttpOnly; Path=/; SameSite=Strict";
                    exchange.getResponseHeaders().add("Set-Cookie", cookie);

                    // CSRF Token
                    String csrfToken = db.generateAndSaveCsrfToken(userId);

                    JsonObject response = new JsonObject();
                    response.addProperty("success", true);
                    response.addProperty("token", token);
                    response.addProperty("csrfToken", csrfToken);
                    response.addProperty("role", db.isAdmin(userId) ? "ADMIN" : "USER");
                    sendResponse(exchange, 200, gson.toJson(response));
                } else {
                    attemptInfo.recordFailure();
                    sendResponse(exchange, 401, errorJson("Invalid username or password"));
                }
            } catch (Exception e) {
                System.err.println("[LOGIN ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("An unexpected error occurred. Code: AUTH-500"));
            }
        }
    }

    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
            String user = json.has("username") ? json.get("username").getAsString().trim() : "";
            String email = json.has("email") ? json.get("email").getAsString().trim().toLowerCase() : "";
            String pass = json.has("password") ? json.get("password").getAsString() : "";
            String confirmPass = json.has("confirmPassword") ? json.get("confirmPassword").getAsString() : "";

            // Input validation
            if (user.isEmpty() || user.length() < 3 || user.length() > 50) {
                sendResponse(exchange, 400, errorJson("Username must be 3-50 characters"));
                return;
            }
            if (!user.matches("^[a-zA-Z0-9_]+$")) {
                sendResponse(exchange, 400, errorJson("Username can only contain letters, numbers, and underscores"));
                return;
            }
            if (email.isEmpty() || !isValidEmail(email)) {
                sendResponse(exchange, 400, errorJson("Invalid email address format"));
                return;
            }
            if (pass.isEmpty() || pass.length() < 6) {
                sendResponse(exchange, 400, errorJson("Password must be at least 6 characters"));
                return;
            }

            // Password confirmation check
            if (!pass.equals(confirmPass)) {
                sendResponse(exchange, 400, errorJson("Passwords do not match"));
                return;
            }

            try {
                if (!db.testConnection())
                    db.connect();

                // Check for duplicates with specific error messages
                if (db.usernameExists(user)) {
                    sendResponse(exchange, 409, errorJson("Username already exists"));
                    return;
                }
                if (db.emailExists(email)) {
                    sendResponse(exchange, 409, errorJson("Email already exists"));
                    return;
                }

                boolean success = db.registerUser(user, email, pass);
                if (success) {
                    // Make first user admin automatically
                    var users = db.getAllUsers();
                    if (users.size() == 1) {
                        db.setUserRole(users.get(0).id(), "ADMIN");
                    }
                    sendResponse(exchange, 200, "{\"success\": true, \"message\": \"Account created successfully\"}");
                } else {
                    sendResponse(exchange, 409, errorJson("Registration failed"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }
    }

    static class TwoFactorHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            if (!"POST".equals(method)) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            String token = getToken(exchange);
            if (token == null || !sessions.containsKey(token)) {
                sendResponse(exchange, 401, errorJson("Unauthorized"));
                return;
            }
            int userId = sessions.get(token);

            try {
                if (!db.testConnection())
                    db.connect();

                if (path.endsWith("/setup")) {
                    String secret = TotpUtil.generateSecret();
                    String username = db.getUser(userId).username();
                    String qrUrl = TotpUtil.getQrCodeUrl(username, "Barron", secret);

                    db.update2FA(userId, secret, false);

                    JsonObject response = new JsonObject();
                    response.addProperty("secret", secret);
                    response.addProperty("qrUrl", qrUrl);
                    sendResponse(exchange, 200, gson.toJson(response));

                } else if (path.endsWith("/enable")) {
                    JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                    String codeRaw = json.get("code").getAsString();

                    var user = db.getUser(userId);
                    if (user.twoFactorSecret() == null) {
                        sendResponse(exchange, 400, errorJson("2FA not setup"));
                        return;
                    }

                    if (TotpUtil.verifyCode(user.twoFactorSecret(), Integer.parseInt(codeRaw))) {
                        db.update2FA(userId, user.twoFactorSecret(), true);
                        sendResponse(exchange, 200, "{\"success\": true}");
                    } else {
                        sendResponse(exchange, 400, errorJson("Invalid code"));
                    }
                } else if (path.endsWith("/disable")) {
                    db.update2FA(userId, null, false);
                    sendResponse(exchange, 200, "{\"success\": true}");
                } else {
                    sendResponse(exchange, 404, errorJson("Endpoint not found"));
                }
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }
    }

    static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String token = getToken(exchange);
            if (token != null)
                sessions.remove(token);
            sendResponse(exchange, 200, "{\"success\": true}");
        }
    }

    // ==================== DASHBOARD HANDLER ====================

    static class UserDashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String token = getToken(exchange);
            if (token == null || !sessions.containsKey(token)) {
                sendResponse(exchange, 401, errorJson("Unauthorized"));
                return;
            }
            int userId = sessions.get(token);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            try {
                if (!db.testConnection())
                    db.connect();

                // GET /api/user/profile
                if (path.endsWith("/profile")) {
                    if ("GET".equals(method)) {
                        var user = db.getUser(userId);
                        sendResponse(exchange, 200, gson.toJson(user));
                    } else if ("POST".equals(method)) {
                        JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                        db.updateUser(userId, json.get("email").getAsString(),
                                json.has("password") ? json.get("password").getAsString() : null);
                        sendResponse(exchange, 200, "{\"success\": true}");
                    }
                }
                // GET /api/user/licenses
                else if (path.endsWith("/licenses")) {
                    if ("GET".equals(method)) {
                        List<?> licenses = db.getLicensesForUser(userId);
                        sendResponse(exchange, 200, gson.toJson(licenses));
                    }
                }
                // POST /api/user/licenses/add (Bind)
                else if (path.endsWith("/licenses/add")) {
                    JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                    String key = json.get("key").getAsString();
                    boolean success = db.bindLicenseToUser(userId, key);

                    // Send activation email on success
                    if (success) {
                        try {
                            String userEmail = db.getEmailForUser(userId);
                            String productName = db.getProductNameForLicense(key);
                            if (userEmail != null && !userEmail.isEmpty()) {
                                if (productName == null || productName.isEmpty())
                                    productName = "Product";
                                String emailBody = """
                                        Hello,

                                        Thank you for activating your license! Your license has been successfully linked to your account.

                                        License Key: %s
                                        Product: %s

                                        You can now download your product from your dashboard at any time.

                                        If you have any questions, please don't hesitate to contact our support team.

                                        Best regards,
                                        Barron Team
                                        """
                                        .formatted(key, productName);
                                sendEmail(userEmail, "License Activated Successfully - " + productName, emailBody);
                            }
                        } catch (Exception e) {
                            System.err.println("[EMAIL] Failed to send activation email: " + e.getMessage());
                        }
                    }

                    JsonObject resp = new JsonObject();
                    resp.addProperty("success", success);
                    resp.addProperty("message", success ? "License added!" : "License invalid or already claimed.");
                    sendResponse(exchange, 200, gson.toJson(resp));
                }
                // POST /api/user/licenses/ips (Update IPs)
                else if (path.endsWith("/ips")) {
                    JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                    int licenseId = json.get("licenseId").getAsInt();
                    List<String> ips = new ArrayList<>();
                    if (json.has("ip1"))
                        ips.add(json.get("ip1").getAsString());
                    if (json.has("ip2"))
                        ips.add(json.get("ip2").getAsString());

                    // Verify ownership? Ideally yes, but for now assuming ID is valid from list.
                    // TODO: Check if licenseId belongs to userId.
                    // For MVP simplicity, we trust the ID or assume non-malicious.
                    // To be safe: filter getLicensesForUser stream.
                    boolean owns = db.getLicensesForUser(userId).stream().anyMatch(l -> l.id() == licenseId);
                    if (!owns) {
                        sendResponse(exchange, 403, errorJson("Not your license"));
                        return;
                    }

                    db.setLicenseIps(licenseId, ips);
                    sendResponse(exchange, 200, "{\"success\": true}");
                }
                // GET /api/user/licenses/{id}/download
                else if (path.matches(".*/licenses/\\d+/download") && "GET".equals(method)) {
                    String[] segments = path.split("/");
                    // Path: /api/user/licenses/{id}/download
                    // segments: ["", "api", "user", "licenses", "{id}", "download"]
                    int licenseId = Integer.parseInt(segments[4]);

                    // Verify ownership
                    var userLicenses = db.getLicensesForUser(userId);
                    var license = userLicenses.stream().filter(l -> l.id() == licenseId).findFirst().orElse(null);

                    if (license == null) {
                        sendResponse(exchange, 403, errorJson("License not found or access denied"));
                        return;
                    }

                    // Get product file
                    DatabaseManager.ProductInfo product = db.getProduct(license.productId());
                    if (product == null || product.filePath() == null || product.filePath().isEmpty()) {
                        sendResponse(exchange, 404, errorJson("No file associated with this product"));
                        return;
                    }

                    java.io.File file = new java.io.File(product.filePath());
                    if (!file.exists()) {
                        sendResponse(exchange, 404, errorJson("File not found on server"));
                        return;
                    }

                    // Stream file
                    exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                    exchange.getResponseHeaders().set("Content-Disposition",
                            "attachment; filename=\"" + product.fileName() + "\"");
                    exchange.sendResponseHeaders(200, file.length());
                    try (java.io.OutputStream os = exchange.getResponseBody();
                            java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
                        fis.transferTo(os);
                    }

                } else {
                    sendResponse(exchange, 404, errorJson("Endpoint not found"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson(e.getMessage()));
            }
        }
    }

    static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if ("/".equals(path))
                path = "/index.html";

            // Prevent path traversal
            if (path.contains("..")) {
                send404(exchange);
                return;
            }

            try (java.io.InputStream is = LicenseServer.class.getResourceAsStream("/web" + path)) {
                if (is == null) {
                    send404(exchange);
                    return;
                }
                byte[] bytes = is.readAllBytes();

                // Set Content-Type
                String contentType = "application/octet-stream";
                if (path.endsWith(".html"))
                    contentType = "text/html";
                else if (path.endsWith(".css"))
                    contentType = "text/css";
                else if (path.endsWith(".js"))
                    contentType = "application/javascript";
                else if (path.endsWith(".png"))
                    contentType = "image/png";
                else if (path.endsWith(".jpg") || path.endsWith(".jpeg"))
                    contentType = "image/jpeg";
                else if (path.endsWith(".svg"))
                    contentType = "image/svg+xml";

                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        }

        private void send404(HttpExchange exchange) throws IOException {
            String response = "404 Not Found";
            exchange.sendResponseHeaders(404, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }

    }

    // Helper methods
    private static String getRequestBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static String getToken(HttpExchange exchange) {
        // 1. Check Authorization header (Bearer token)
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }
        // 2. Check session_token cookie (set by LoginHandler)
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader != null) {
            for (String cookie : cookieHeader.split(";")) {
                cookie = cookie.trim();
                if (cookie.startsWith("session_token=")) {
                    return cookie.substring("session_token=".length());
                }
            }
        }
        // 3. Fallback: Check query parameter for downloads
        Map<String, String> params = queryToMap(exchange.getRequestURI().getQuery());
        if (params.containsKey("token")) {
            return params.get("token");
        }
        return null;
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);

        // Security Headers
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff"); // Prevent MIME sniffing
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY"); // Prevent clickjacking
        exchange.getResponseHeaders().set("X-XSS-Protection", "1; mode=block"); // Enable browser XSS filter
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'self'"); // XSS mitigation
        exchange.getResponseHeaders().set("Referrer-Policy", "strict-origin-when-cross-origin"); // Prevent info leakage
        exchange.getResponseHeaders().set("Cache-Control", "no-store, no-cache, must-revalidate"); // Prevent caching
                                                                                                   // sensitive data

        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * HTML escape to prevent XSS attacks
     * Use when embedding user data in HTML responses
     */
    private static String escapeHtml(String input) {
        if (input == null)
            return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    private static String errorJson(String msg) {
        JsonObject json = new JsonObject();
        json.addProperty("valid", false);
        json.addProperty("error", msg);
        return gson.toJson(json);
    }

    private static Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null)
            return result;
        for (String param : query.split("&")) {
            String[] entry = param.split("=", 2);
            if (entry.length > 1) {
                try {
                    result.put(
                            URLDecoder.decode(entry[0], StandardCharsets.UTF_8),
                            URLDecoder.decode(entry[1], StandardCharsets.UTF_8));
                } catch (Exception e) {
                    result.put(entry[0], entry[1]);
                }
            } else {
                result.put(entry[0], "");
            }
        }
        return result;
    }

    private static String getCsrfToken(HttpExchange exchange) {
        return exchange.getRequestHeaders().getFirst("X-CSRF-Token");
    }

    private static String getClientIp(HttpExchange exchange) {
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    /**
     * Comprehensive email validation
     * - RFC 5322 compliant format
     * - No consecutive dots
     * - Valid TLD (2-10 chars)
     * - Reasonable length limits
     */
    private static boolean isValidEmail(String email) {
        if (email == null || email.length() < 5 || email.length() > 254) {
            return false;
        }

        // Check for common typos/invalid patterns
        if (email.contains("..") || email.startsWith(".") || email.contains(" ")) {
            return false;
        }

        // RFC 5322 compliant regex with stricter rules
        // Local part: letters, digits, !#$%&'*+/=?^_`{|}~- and dots (not consecutive/at
        // start/end)
        // Domain: letters, digits, hyphens, dots, TLD 2-10 chars
        String emailRegex = "^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,10}$";

        if (!email.matches(emailRegex)) {
            return false;
        }

        // Additional checks for common mistakes
        String[] parts = email.split("@");
        if (parts.length != 2)
            return false;

        String localPart = parts[0];
        String domain = parts[1];

        // Local part length check (max 64 chars per RFC)
        if (localPart.length() > 64 || localPart.isEmpty()) {
            return false;
        }

        // Domain sanity checks
        if (domain.startsWith("-") || domain.endsWith("-") || domain.startsWith(".")) {
            return false;
        }

        // Check for common typos in popular domains
        String[] invalidDomains = { "gamil.com", "gmial.com", "gnail.com", "gmal.com", "gmail.con",
                "hotmal.com", "hotmail.con", "yaho.com", "yahoo.con",
                "outlok.com", "outlook.con", "test.test", "example.example" };
        for (String invalid : invalidDomains) {
            if (domain.equalsIgnoreCase(invalid)) {
                return false;
            }
        }

        return true;
    }

    // ==================== PASSWORD RESET HANDLERS ====================

    static class ForgotPasswordHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
            String email = json.has("email") ? json.get("email").getAsString().trim().toLowerCase() : "";

            // Rate Limit Check (15 requests per hour per IP)
            String ip = exchange.getRemoteAddress().getAddress().getHostAddress();
            if (isRateLimited("RESET:" + ip, RESET_RATE_LIMIT_MAX, RESET_RATE_LIMIT_WINDOW)) {
                sendResponse(exchange, 429,
                        errorJson("Too many password reset requests. Please try again in an hour."));
                return;
            }

            try {
                if (!db.testConnection())
                    db.connect();
                String token = db.createPasswordResetToken(email);
                // In production, send email with reset link containing token
                // For now, just return success (don't reveal if email exists)
                if (token != null) {
                    System.out.println("[PASSWORD RESET] Token created for email: " + email);
                    // Build reset link using configured domain or localhost fallback
                    String baseUrl;
                    if (serverDomain != null && !serverDomain.isEmpty()) {
                        // Use configured domain (for Cloudflare/production)
                        if (serverDomain.toLowerCase().startsWith("http://")
                                || serverDomain.toLowerCase().startsWith("https://")) {
                            baseUrl = serverDomain;
                        } else {
                            String protocol = sslEnabled ? "https" : "http";
                            baseUrl = protocol + "://" + serverDomain;
                        }
                    } else {
                        // Fallback to localhost
                        baseUrl = "http://localhost:" + webPort;
                    }
                    String resetLink = baseUrl + "/#view-reset?token=" + token;

                    sendEmail(email, "Password Reset Request",
                            "Hello,\n\nYou have requested to reset your password. Click the link below:\n\n"
                                    + resetLink
                                    + "\n\nThis link expires in 10 minutes and can only be used once.\n\nBarron Team");
                    System.out.println("[PASSWORD RESET] Email send attempt completed for: " + email);
                } else {
                    System.out.println("[PASSWORD RESET] No user found with email: " + email + " (no token created)");
                }

                JsonObject response = new JsonObject();
                response.addProperty("success", true);
                response.addProperty("message", "If the email exists, a reset link has been sent.");
                sendResponse(exchange, 200, gson.toJson(response));
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }
    }

    // ... (ResetPasswordHandler) ...

    // ==================== HELPER METHODS ====================

    // Helper to send email
    private static void sendEmail(String to, String subject, String body) {
        DatabaseManager.SmtpConfig config = db.getSmtpSettings();
        if (config == null || !config.isEnabled()) {
            System.out.println("[SMTP DISABLED] Would send email to " + to + ": " + subject);
            return;
        }

        String security = config.security();
        if (security == null || security.isEmpty())
            security = "SSL";

        java.util.Properties props = new java.util.Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", config.host());
        props.put("mail.smtp.port", String.valueOf(config.port()));
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");

        // Configure based on security type
        switch (security) {
            case "SSL" -> {
                props.put("mail.smtp.ssl.enable", "true");
                props.put("mail.smtp.ssl.trust", config.host());
                props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
                props.put("mail.smtp.socketFactory.port", String.valueOf(config.port()));
            }
            case "TLS", "STARTTLS" -> {
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.starttls.required", "true");
                props.put("mail.smtp.ssl.trust", config.host());
            }
            // "Yok" - no security
        }

        try {
            javax.mail.Session session = javax.mail.Session.getInstance(props, new javax.mail.Authenticator() {
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(config.user(), config.pass());
                }
            });

            String protocol = "SSL".equals(security) ? "smtps" : "smtp";
            javax.mail.Message message = new javax.mail.internet.MimeMessage(session);
            message.setFrom(new javax.mail.internet.InternetAddress(config.fromEmail()));
            message.setRecipients(javax.mail.Message.RecipientType.TO,
                    javax.mail.internet.InternetAddress.parse(to));
            message.setSubject(subject);
            message.setText(body);
            javax.mail.Transport.send(message);
            System.out.println("[SMTP] Email sent to " + to);
        } catch (javax.mail.AuthenticationFailedException e) {
            System.err.println("[SMTP AUTH ERROR] Authentication failed: " + e.getMessage());
            MainWindow.globalLog("[SMTP] Kimlik doğrulama hatası - kullanıcı/şifre kontrol edin");
        } catch (javax.mail.MessagingException e) {
            System.err.println("[SMTP ERROR] " + e.getMessage());
            MainWindow.globalLog("[SMTP] Email gönderme hatası: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[SMTP ERROR] Unexpected: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static class ResetPasswordHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
            String token = json.has("token") ? json.get("token").getAsString() : "";
            String password = json.has("password") ? json.get("password").getAsString() : "";
            String confirmPassword = json.has("confirmPassword") ? json.get("confirmPassword").getAsString() : "";

            if (password.length() < 6) {
                sendResponse(exchange, 400, errorJson("Password must be at least 6 characters"));
                return;
            }
            if (!password.equals(confirmPassword)) {
                sendResponse(exchange, 400, errorJson("Passwords do not match"));
                return;
            }

            try {
                if (!db.testConnection())
                    db.connect();
                boolean success = db.resetPassword(token, password);
                if (success) {
                    sendResponse(exchange, 200, "{\"success\": true, \"message\": \"Password reset successfully\"}");
                } else {
                    sendResponse(exchange, 400, errorJson("Invalid or expired reset token"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }
    }

    // ==================== PRODUCT HANDLER (PUBLIC) ====================

    static class ProductHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            if ("GET".equals(method)) {
                try {
                    if (!db.testConnection())
                        db.connect();
                    var products = db.getActiveProducts();
                    sendResponse(exchange, 200, gson.toJson(products));
                } catch (SQLException e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, errorJson("Server error"));
                }
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }
    }

    // ==================== ADMIN HANDLER ====================

    static class AdminHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String token = getToken(exchange);
            if (token == null || !sessions.containsKey(token)) {
                sendResponse(exchange, 401, errorJson("Unauthorized"));
                return;
            }

            int userId = sessions.get(token);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            String clientIp = getClientIp(exchange);

            try {
                if (!db.testConnection())
                    db.connect();

                // Check admin permission
                if (!db.isAdmin(userId)) {
                    sendResponse(exchange, 403, errorJson("Admin access required"));
                    return;
                }

                // CSRF check for state-changing operations
                if (!"GET".equals(method)) {
                    String csrfToken = getCsrfToken(exchange);
                    if (!db.validateCsrfToken(userId, csrfToken)) {
                        sendResponse(exchange, 403, errorJson("Invalid CSRF token"));
                        return;
                    }
                }

                // Route handling
                if (path.endsWith("/users") || path.matches(".*/users/\\d+")) {
                    handleUsers(exchange, userId, path, method, clientIp);
                } else if (path.endsWith("/products") || path.matches(".*/products/\\d+(/file)?")) {
                    handleAdminProducts(exchange, userId, path, method, clientIp);
                } else if (path.endsWith("/licenses")) {
                    handleAdminLicenses(exchange, method);
                } else if (path.endsWith("/orders")) {
                    handleAdminOrders(exchange, method);
                } else if (path.contains("/payment-visibility")) {
                    handlePaymentVisibility(exchange, method);
                } else if (path.contains("/payment-settings")) {
                    handlePaymentSettings(exchange, userId, method, clientIp);
                } else if (path.endsWith("/logs")) {
                    handleAdminLogs(exchange, method);
                } else if (path.endsWith("/stats")) {
                    handleAdminStats(exchange, method);
                } else if (path.endsWith("/plugins")) {
                    handleAdminPlugins(exchange, method);
                } else if (path.endsWith("/settings")) {
                    handleSystemSettings(exchange, method);
                } else if (path.endsWith("/smtp-settings")) {
                    handleSmtpSettings(exchange, method);
                } else if (path.endsWith("/footer-links")) {
                    handleFooterLinks(exchange, method);
                } else {
                }
            } catch (Throwable e) {
                e.printStackTrace();
                // Ensure response is sent even on OOM if possible (though OOM might prevent
                // object creation)
                try {
                    sendResponse(exchange, 500, errorJson("Server error: " + e.getMessage()));
                } catch (IOException io) {
                    // Ignore if connection already closed
                }
            }
        }

        private void handleSmtpSettings(HttpExchange exchange, String method) throws IOException, SQLException {
            if ("GET".equals(method)) {
                DatabaseManager.SmtpConfig config = db.getSmtpSettings();
                JsonObject json = new JsonObject();
                json.addProperty("host", config.host());
                json.addProperty("port", config.port());
                json.addProperty("security", config.security());
                json.addProperty("username", config.user());
                // Mask password
                json.addProperty("password", config.pass().isEmpty() ? "" : "****");
                json.addProperty("fromEmail", config.fromEmail());
                json.addProperty("isEnabled", config.isEnabled());
                sendResponse(exchange, 200, gson.toJson(json));
            } else if ("POST".equals(method)) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                db.saveSmtpSettings(
                        json.get("host").getAsString(),
                        json.get("port").getAsInt(),
                        json.has("security") ? json.get("security").getAsString() : "SSL",
                        json.get("username").getAsString(),
                        json.get("password").getAsString(),
                        json.get("fromEmail").getAsString(),
                        json.get("isEnabled").getAsBoolean());
                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handlePaymentVisibility(HttpExchange exchange, String method) throws IOException, SQLException {
            if ("GET".equals(method)) {
                var settings = db.getPaymentSettings();
                JsonObject json = new JsonObject();
                // Return visibility flags (stripeActive, paytrActive, shopierActive)
                json.addProperty("stripeActive", settings != null && settings.stripeActive());
                json.addProperty("paytrActive", settings != null && settings.paytrActive());
                json.addProperty("shopierActive", settings != null && settings.shopierActive());
                sendResponse(exchange, 200, gson.toJson(json));
            } else if ("POST".equals(method)) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                boolean stripeActive = json.has("stripeActive") && json.get("stripeActive").getAsBoolean();
                boolean paytrActive = json.has("paytrActive") && json.get("paytrActive").getAsBoolean();
                boolean shopierActive = json.has("shopierActive") && json.get("shopierActive").getAsBoolean();
                db.savePaymentVisibility(stripeActive, paytrActive, shopierActive);
                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminPlugins(HttpExchange exchange, String method) throws IOException, SQLException {
            if ("GET".equals(method)) {
                var plugins = db.getAllPlugins();
                sendResponse(exchange, 200, gson.toJson(plugins));
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleFooterLinks(HttpExchange exchange, String method) throws IOException, SQLException {
            if ("GET".equals(method)) {
                var links = db.getFooterLinks();
                JsonObject response = new JsonObject();
                response.addProperty("discord", links.discord() != null ? links.discord() : "");
                response.addProperty("spigot", links.spigot() != null ? links.spigot() : "");
                response.addProperty("builtbybit", links.builtbybit() != null ? links.builtbybit() : "");
                sendResponse(exchange, 200, gson.toJson(response));
            } else if ("POST".equals(method)) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                String discord = json.has("discord") ? json.get("discord").getAsString() : "";
                String spigot = json.has("spigot") ? json.get("spigot").getAsString() : "";
                String builtbybit = json.has("builtbybit") ? json.get("builtbybit").getAsString() : "";
                db.setFooterLinks(discord, spigot, builtbybit);
                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        // Helper to send email (delegates to outer static method)
        private void sendEmail(String to, String subject, String body) {
            LicenseServer.sendEmail(to, subject, body);
        }

        private void handleSystemSettings(HttpExchange exchange, String method) throws IOException {
            if ("GET".equals(method)) {
                JsonObject settings = new JsonObject();
                settings.addProperty("failoverEnabled", db.isFailoverEnabled());
                settings.addProperty("secondaryHost", db.getSecondaryHost());
                settings.addProperty("secondaryPort", db.getSecondaryPort());
                settings.addProperty("secondaryUser", db.getSecondaryUser());
                // We don't expose passwords or specific hosts for security usually,
                // but since this is ADMIN panel settings, we need to show them to be editable.
                // In a real env, mask them. For this user request:
                // We need to add getters to DatabaseManager first if we want to show existing
                // values.
                // Assuming we just want to ENABLE/DISABLE for now or allow overwrite.

                // Let's assume we allow overwriting.
                // But wait, the user wants "Optional in settings". Use Failover flag.
                sendResponse(exchange, 200, gson.toJson(settings));
            } else if ("POST".equals(method)) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);

                if (json.has("failoverEnabled")) {
                    boolean enabled = json.get("failoverEnabled").getAsBoolean();
                    db.setFailoverEnabled(enabled);
                }

                if (json.has("secondaryHost")) {
                    String host = json.get("secondaryHost").getAsString();
                    int port = json.has("secondaryPort") ? json.get("secondaryPort").getAsInt() : 3306;
                    String user = json.has("secondaryUser") ? json.get("secondaryUser").getAsString() : "";
                    String pass = json.has("secondaryPass") ? json.get("secondaryPass").getAsString() : "";

                    if (!host.isEmpty()) {
                        db.configureSecondary(host, port, user, pass);
                    }
                }

                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleUsers(HttpExchange exchange, int adminId, String path, String method, String ip)
                throws SQLException, IOException {
            if ("GET".equals(method) && path.endsWith("/users")) {
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> queryParams = queryToMap(query);
                List<DatabaseManager.UserInfo> users;

                if (queryParams.containsKey("q") && !queryParams.get("q").isEmpty()) {
                    users = db.searchUsers(queryParams.get("q"));
                } else {
                    users = db.getAllUsers();
                }
                sendResponse(exchange, 200, gson.toJson(users));

            } else if ("DELETE".equals(method) && path.matches(".*/users/\\d+")) {
                int targetId = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
                if (targetId == adminId) {
                    sendResponse(exchange, 400, errorJson("Cannot delete yourself"));
                    return;
                }
                db.deleteUser(targetId);
                db.logAdminAction(adminId, "DELETE_USER", "USER", targetId, null, ip);
                sendResponse(exchange, 200, "{\"success\": true}");

            } else if ("POST".equals(method) && path.matches(".*/users/\\d+")) {
                int targetId = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);

                if (json.has("role")) {
                    String role = json.get("role").getAsString();
                    db.setUserRole(targetId, role);
                    db.logAdminAction(adminId, "SET_ROLE", "USER", targetId, "role=" + role, ip);
                }
                if (json.has("isActive")) {
                    boolean active = json.get("isActive").getAsBoolean();
                    db.setUserActive(targetId, active);
                    db.logAdminAction(adminId, active ? "ACTIVATE_USER" : "DEACTIVATE_USER", "USER", targetId, null,
                            ip);
                }
                if (json.has("balance")) {
                    double balance = json.get("balance").getAsDouble();
                    db.setBalance(targetId, balance);
                    db.logAdminAction(adminId, "SET_BALANCE", "USER", targetId, "balance=" + balance, ip);
                }
                // Handle license duration updates if passed (optional, for future)

                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminProducts(HttpExchange exchange, int adminId, String path, String method, String ip)
                throws SQLException, IOException {
            if ("GET".equals(method)) {
                var products = db.getAllProducts();
                sendResponse(exchange, 200, gson.toJson(products));
            } else if ("POST".equals(method) && path.endsWith("/products")) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                int id = db.addProduct(
                        json.get("name").getAsString(),
                        json.has("description") ? json.get("description").getAsString() : "",
                        json.get("price").getAsDouble(),
                        json.has("currency") ? json.get("currency").getAsString() : "USD",
                        json.has("actionType") ? json.get("actionType").getAsString() : "REDIRECT",
                        json.has("actionConfig") ? json.get("actionConfig").getAsString() : "",
                        json.has("pluginId") ? json.get("pluginId").getAsInt() : null);
                db.logAdminAction(adminId, "CREATE_PRODUCT", "PRODUCT", id, json.get("name").getAsString(), ip);

                if (json.has("fileData") && json.has("fileName")) {
                    saveProductFile(id, json.get("fileName").getAsString(), json.get("fileData").getAsString());
                }

                sendResponse(exchange, 200, "{\"success\": true, \"id\": " + id + "}");
            } else if ("POST".equals(method) && path.endsWith("/file")) {
                // Streaming Upload Handler
                String fileName = exchange.getRequestHeaders().getFirst("X-File-Name");
                if (fileName == null || fileName.isEmpty()) {
                    sendResponse(exchange, 400, errorJson("Missing X-File-Name header"));
                    return;
                }

                int productId = -1;
                try {
                    String[] parts = path.split("/");
                    // Path format: /api/admin/products/{id}/file
                    // parts: ["", "api", "admin", "products", "{id}", "file"]
                    productId = Integer.parseInt(parts[4]);
                } catch (Exception e) {
                    sendResponse(exchange, 400, errorJson("Invalid product ID"));
                    return;
                }

                File uploadsDir = new File("uploads");
                if (!uploadsDir.exists())
                    uploadsDir.mkdirs();

                String safeName = System.currentTimeMillis() + "_" + fileName.replaceAll("[^a-zA-Z0-9._-]", "");
                File dest = new File(uploadsDir, safeName);

                try (java.io.InputStream in = exchange.getRequestBody();
                        java.io.FileOutputStream out = new java.io.FileOutputStream(dest)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, errorJson("File upload failed"));
                    return;
                }

                // Update database
                db.setProductFile(productId, dest.getAbsolutePath(), fileName);
                db.logAdminAction(adminId, "UPLOAD_FILE", "PRODUCT", productId, fileName, ip);

                sendResponse(exchange, 200, "{\"success\": true}");
            } else if ("PUT".equals(method) && path.matches(".*/products/\\d+")) {
                int productId = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                db.updateProduct(productId,
                        json.get("name").getAsString(),
                        json.has("description") ? json.get("description").getAsString() : "",
                        json.get("price").getAsDouble(),
                        json.has("currency") ? json.get("currency").getAsString() : "USD",
                        json.has("actionType") ? json.get("actionType").getAsString() : "REDIRECT",
                        json.has("actionConfig") ? json.get("actionConfig").getAsString() : "",
                        json.has("pluginId") ? json.get("pluginId").getAsInt() : null,
                        json.has("isActive") ? json.get("isActive").getAsBoolean() : true);

                if (json.has("fileData") && json.has("fileName")) {
                    saveProductFile(productId, json.get("fileName").getAsString(), json.get("fileData").getAsString());
                }

                db.logAdminAction(adminId, "UPDATE_PRODUCT", "PRODUCT", productId, null, ip);
                sendResponse(exchange, 200, "{\"success\": true}");
            } else if ("DELETE".equals(method) && path.matches(".*/products/\\d+")) {
                int productId = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
                db.deleteProduct(productId);
                db.logAdminAction(adminId, "DELETE_PRODUCT", "PRODUCT", productId, null, ip);
                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminLicenses(HttpExchange exchange, String method) throws SQLException, IOException {
            if ("GET".equals(method)) {
                var licenses = db.getAllLicenses();
                sendResponse(exchange, 200, gson.toJson(licenses));
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminOrders(HttpExchange exchange, String method) throws SQLException, IOException {
            if ("GET".equals(method)) {
                var orders = db.getAllOrders();
                sendResponse(exchange, 200, gson.toJson(orders));
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handlePaymentSettings(HttpExchange exchange, int adminId, String method, String ip)
                throws SQLException, IOException {
            if ("GET".equals(method)) {
                var s = db.getPaymentSettings();
                // Mask API keys for security
                JsonObject obj = new JsonObject();
                obj.addProperty("provider", s.provider());
                obj.addProperty("apiKey",
                        s.apiKey() != null && !s.apiKey().isEmpty()
                                ? "****" + s.apiKey().substring(Math.max(0, s.apiKey().length() - 4))
                                : "");
                obj.addProperty("isEnabled", s.isEnabled());
                obj.addProperty("isTestMode", s.isTestMode());
                obj.addProperty("merchantId", s.merchantId());

                JsonArray masked = new JsonArray();
                masked.add(obj);

                sendResponse(exchange, 200, gson.toJson(masked));
            } else if ("POST".equals(method)) {
                JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
                db.savePaymentSettings(
                        json.get("provider").getAsString(),
                        json.has("apiKey") ? json.get("apiKey").getAsString() : "",
                        json.has("apiSecret") ? json.get("apiSecret").getAsString() : "",
                        json.has("webhookSecret") ? json.get("webhookSecret").getAsString() : "",
                        json.has("merchantId") ? json.get("merchantId").getAsString() : "",
                        json.has("isEnabled") ? json.get("isEnabled").getAsBoolean() : false,
                        json.has("isTestMode") ? json.get("isTestMode").getAsBoolean() : true);
                db.logAdminAction(adminId, "UPDATE_PAYMENT_SETTINGS", "PAYMENT", null,
                        json.get("provider").getAsString(), ip);
                sendResponse(exchange, 200, "{\"success\": true}");
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminLogs(HttpExchange exchange, String method) throws SQLException, IOException {
            if ("GET".equals(method)) {
                var logs = db.getAdminLogs(100);
                sendResponse(exchange, 200, gson.toJson(logs));
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }

        private void handleAdminStats(HttpExchange exchange, String method) throws SQLException, IOException {
            if ("GET".equals(method)) {
                JsonObject stats = new JsonObject();
                var counts = db.getStatsCounts();
                stats.addProperty("totalUsers", counts.getOrDefault("users", 0L));
                stats.addProperty("totalLicenses", counts.getOrDefault("licenses", 0L));
                stats.addProperty("totalProducts", counts.getOrDefault("products", 0L));
                stats.addProperty("totalOrders", counts.getOrDefault("orders", 0L));
                sendResponse(exchange, 200, gson.toJson(stats));
            } else {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
            }
        }
    }

    // ==================== SETTINGS HANDLER (Public) ====================

    static class SettingsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            try {
                if (!db.testConnection())
                    db.connect();

                if (path.endsWith("/footer-links") && "GET".equals(method)) {
                    var links = db.getFooterLinks();
                    JsonObject response = new JsonObject();
                    response.addProperty("discord", links.discord() != null ? links.discord() : "");
                    response.addProperty("spigot", links.spigot() != null ? links.spigot() : "");
                    response.addProperty("builtbybit", links.builtbybit() != null ? links.builtbybit() : "");
                    sendResponse(exchange, 200, gson.toJson(response));
                } else {
                    sendResponse(exchange, 404, errorJson("Settings endpoint not found"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }
    }

    // ==================== PAYMENT HANDLER ====================

    static class PaymentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            try {
                if (!db.testConnection())
                    db.connect();

                if (path.endsWith("/checkout") && "POST".equals(method)) {
                    handleCheckout(exchange);
                } else if (path.endsWith("/providers") && "GET".equals(method)) {
                    handlePaymentProviders(exchange);
                } else if (path.contains("/webhook/stripe")) {
                    handleStripeWebhook(exchange);
                } else if (path.contains("/webhook/shopier")) {
                    handleShopierWebhook(exchange);
                } else if (path.contains("/webhook/paytr")) {
                    handlePayTRWebhook(exchange);
                } else {
                    sendResponse(exchange, 404, errorJson("Payment endpoint not found"));
                }
            } catch (SQLException e) {
                MainWindow.globalLog("[PAYMENT ERROR] " + e.getMessage());
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Server error"));
            }
        }

        private void handleCheckout(HttpExchange exchange) throws IOException, SQLException {
            String token = getToken(exchange);
            if (token == null || !sessions.containsKey(token)) {
                sendResponse(exchange, 401, errorJson("Unauthorized"));
                return;
            }

            int userId = sessions.get(token);
            JsonObject json = gson.fromJson(getRequestBody(exchange), JsonObject.class);
            if (!json.has("productId") || !json.has("provider")) {
                sendResponse(exchange, 400, errorJson("Missing productId or provider"));
                return;
            }

            int productId = json.get("productId").getAsInt();
            String provider = json.get("provider").getAsString().toUpperCase();

            var product = db.getProduct(productId);
            if (product == null) {
                sendResponse(exchange, 404, errorJson("Product not found"));
                return;
            }

            // Validate Provider
            var settings = db.getPaymentSettings();
            boolean isProviderValid = false;

            if ("BALANCE".equals(provider)) {
                isProviderValid = true; // Always allow balance if sufficient funds (checked later)
            } else if (settings != null) {
                switch (provider) {
                    case "STRIPE":
                        isProviderValid = settings.stripeActive();
                        break;
                    case "PAYTR":
                        isProviderValid = settings.paytrActive();
                        break;
                    case "SHOPIER":
                        isProviderValid = settings.shopierActive();
                        break;
                }
            }

            if (!isProviderValid) {
                sendResponse(exchange, 400, errorJson("Payment provider not active"));
                return;
            }

            // check duplicate/limit logic if needed? Nah.

            // BALANCE LOGIC
            if ("BALANCE".equals(provider)) {
                var user = db.getUser(userId);
                if (user.balance() < product.price()) {
                    sendResponse(exchange, 400, errorJson("Yetersiz bakiye!")); // Insufficient funds
                    return;
                }

                // Atomic deduction
                if (db.deductBalance(userId, product.price())) {
                    // Create Order (PENDING initially)
                    int orderId = db.createOrder(userId, productId, "BALANCE", product.price(), product.currency());

                    // Fulfill immediately
                    if (db.processOrderCompletion(orderId)) {
                        JsonObject response = new JsonObject();
                        response.addProperty("success", true);
                        response.addProperty("message", "Purchase successful!");
                        response.addProperty("orderId", orderId);
                        sendResponse(exchange, 200, gson.toJson(response));
                    } else {
                        // This is bad - money deducted but order failed.
                        // In real world, refund or log critical error.
                        // For now log it.
                        System.err.println("CRITICAL: Money deducted but order failed for user " + userId);
                        sendResponse(exchange, 500, errorJson("Order processing failed. Contact support."));
                    }
                } else {
                    sendResponse(exchange, 400, errorJson("Transaction failed (Balance check/deduct race condition)"));
                }
                return;
            }

            // EXTERNAL PROVIDERS LOGIC
            // Create pending order
            int orderId = db.createOrder(userId, productId, provider, product.price(), product.currency());

            // Generate checkout URL based on provider
            JsonObject response = new JsonObject();
            response.addProperty("success", true);
            response.addProperty("orderId", orderId);
            response.addProperty("provider", provider);

            // In production, integrate with actual payment provider APIs
            // For now, return test checkout info
            switch (provider) {
                case "STRIPE":
                    response.addProperty("message", "Redirect to Stripe checkout");
                    response.addProperty("checkoutUrl", "https://checkout.stripe.com/pay/test_" + orderId);
                    break;
                case "SHOPIER":
                    response.addProperty("action", "FORM_POST");
                    response.addProperty("url", "https://www.shopier.com/ShowProduct/api_pay4.php");

                    JsonObject fields = new JsonObject();

                    // Shopier settings from DB
                    String apiKey = settings.apiKey();
                    String apiSecret = settings.apiSecret();
                    String randomNr = String.valueOf(new Random().nextInt(899999) + 100000); // 6-digit random
                    String platformOrderId = String.valueOf(orderId);
                    String totalOrderValue = String.valueOf(product.price());

                    // Currency Mapping: 0=TL, 1=USD, 2=EUR
                    String currencyCode = "0"; // Default TL
                    if ("USD".equalsIgnoreCase(product.currency()))
                        currencyCode = "1";
                    else if ("EUR".equalsIgnoreCase(product.currency()))
                        currencyCode = "2";

                    // Generate Signature using HMAC-SHA256
                    // Data = random_nr + platform_order_id + total_order_value + currency
                    // Key = API_SECRET
                    String dataToSign = randomNr + platformOrderId + totalOrderValue + currencyCode;
                    String signature = generateShopierHmacSignature(dataToSign, apiSecret);

                    // Get user info for buyer fields
                    String buyerName = "Valued";
                    String buyerSurname = "Customer";
                    String buyerEmail = "customer@barron.dev";
                    String buyerPhone = "05555555555";
                    try {
                        var user = db.getUser(userId);
                        if (user != null) {
                            if (user.email() != null && !user.email().isEmpty()) {
                                buyerEmail = user.email();
                            }
                            if (user.username() != null && !user.username().isEmpty()) {
                                buyerName = user.username();
                                buyerSurname = ""; // Single name for username
                            }
                        }
                    } catch (Exception ignored) {
                    }

                    // Populate Fields (correct field names for Shopier)
                    fields.addProperty("API_key", apiKey); // Note: lowercase 'k' in 'key'
                    fields.addProperty("website_index", "1");
                    fields.addProperty("platform_order_id", platformOrderId);
                    fields.addProperty("product_name", product.name());
                    fields.addProperty("product_type", "1"); // 1 = Digital
                    fields.addProperty("buyer_name", buyerName);
                    fields.addProperty("buyer_surname", buyerSurname);
                    fields.addProperty("buyer_email", buyerEmail);
                    fields.addProperty("buyer_phone", buyerPhone);
                    fields.addProperty("buyer_account_age", "0");
                    fields.addProperty("buyer_id_nr", "");
                    fields.addProperty("billing_address", "Digital Delivery");
                    fields.addProperty("billing_city", "Istanbul");
                    fields.addProperty("billing_country", "TR");
                    fields.addProperty("billing_postcode", "34000");
                    fields.addProperty("shipping_address", "Digital Delivery");
                    fields.addProperty("shipping_city", "Istanbul");
                    fields.addProperty("shipping_country", "TR");
                    fields.addProperty("shipping_postcode", "34000");
                    fields.addProperty("total_order_value", totalOrderValue);
                    fields.addProperty("currency", currencyCode);
                    fields.addProperty("platform", "0");
                    fields.addProperty("is_in_frame", "0");
                    fields.addProperty("current_language", "tr");
                    fields.addProperty("modul_version", "1.0.0");
                    fields.addProperty("random_nr", randomNr);
                    fields.addProperty("signature", signature);

                    response.add("fields", fields);
                    break;
                case "PAYTR":
                    response.addProperty("message", "Redirect to PayTR checkout");
                    response.addProperty("checkoutUrl", "https://www.paytr.com/odeme/test_" + orderId);
                    break;
                default:
                    sendResponse(exchange, 400, errorJson("Unknown payment provider"));
                    return;
            }

            sendResponse(exchange, 200, gson.toJson(response));
        }

        private void handlePaymentProviders(HttpExchange exchange) throws IOException {
            try {
                var settings = db.getPaymentSettings();
                JsonObject response = new JsonObject();
                // If settings are null or not enabled, return all false or defaults
                if (settings == null) {
                    response.addProperty("stripe", false);
                    response.addProperty("paytr", false);
                    response.addProperty("shopier", false);
                } else {
                    response.addProperty("stripe", settings.stripeActive());
                    response.addProperty("paytr", settings.paytrActive());
                    response.addProperty("shopier", settings.shopierActive());
                }
                sendResponse(exchange, 200, gson.toJson(response));
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, errorJson("Internal Server Error"));
            }
        }

        private void handleStripeWebhook(HttpExchange exchange) throws IOException, SQLException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            String payload = getRequestBody(exchange);
            String signature = exchange.getRequestHeaders().getFirst("Stripe-Signature");

            var settings = db.getPaymentSettings();
            if (settings == null || !"STRIPE".equals(settings.provider())) {
                sendResponse(exchange, 400, errorJson("Stripe not configured"));
                return;
            }

            if (signature == null || signature.isEmpty()) {
                sendResponse(exchange, 400, errorJson("Missing signature"));
                return;
            }

            try {
                JsonObject event = gson.fromJson(payload, JsonObject.class);
                String eventType = event.has("type") ? event.get("type").getAsString() : "";

                if ("checkout.session.completed".equals(eventType)) {
                    JsonObject data = event.getAsJsonObject("data").getAsJsonObject("object");
                    String paymentId = data.get("id").getAsString();

                    if (db.orderExistsByProviderId(paymentId)) {
                        sendResponse(exchange, 200, "{\"received\": true, \"message\": \"Already processed\"}");
                        return;
                    }

                    if (db.processOrderCompletion(paymentId)) {
                        System.out.println("[Stripe Webhook] Payment and order completion successful: " + paymentId);
                    } else {
                        System.out.println("[Stripe Webhook] Order completion failed: " + paymentId);
                    }
                }
                sendResponse(exchange, 200, "{\"received\": true}");
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 400, errorJson("Webhook processing error"));
            }
        }

        private void handleShopierWebhook(HttpExchange exchange) throws IOException, SQLException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }

            String payload = getRequestBody(exchange);
            Map<String, String> params = new HashMap<>();
            try {
                for (String pair : payload.split("&")) {
                    String[] kv = pair.split("=");
                    if (kv.length >= 2) {
                        params.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                                URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                    }
                }
            } catch (Exception e) {
                System.err.println("Error parsing Shopier webhook: " + e.getMessage());
            }

            String status = params.get("status");
            String platformOrderId = params.get("platform_order_id");
            String paymentId = params.get("payment_id");
            String signature = params.get("signature");

            // Verify Shopier webhook signature
            var settings = db.getPaymentSettings();
            if (settings != null && settings.apiSecret() != null && !settings.apiSecret().isEmpty()) {
                String expectedData = params.getOrDefault("random_nr", "")
                        + params.getOrDefault("platform_order_id", "")
                        + params.getOrDefault("total_order_value", "")
                        + params.getOrDefault("currency", "");
                String expectedSignature = generateShopierHmacSignature(expectedData, settings.apiSecret());
                if (signature == null || !signature.equals(expectedSignature)) {
                    System.err.println("[SHOPIER WEBHOOK] Invalid signature! Expected: " + expectedSignature
                            + " Got: " + signature);
                    sendResponse(exchange, 403, errorJson("Invalid webhook signature"));
                    return;
                }
            }
            System.out.println("[SHOPIER WEBHOOK] Signature verified for order: " + platformOrderId);

            if ("success".equalsIgnoreCase(status)) {
                int orderId = -1;
                try {
                    orderId = Integer.parseInt(platformOrderId);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid Shopier Order ID: " + platformOrderId);
                    return;
                }

                // Update Order with Payment ID (Shopier ID)
                db.updateOrderStatus(orderId, "PENDING", paymentId);

                if (db.processOrderCompletion(orderId)) {
                    System.out.println("Shopier Order " + orderId + " completed.");
                } else {
                    System.out.println("Shopier Order " + orderId + " failed or already done.");
                }
            } else {
                System.out.println("Shopier payment failed for order " + platformOrderId);
            }

            String response = "OK";
            exchange.sendResponseHeaders(200, response.length());
            try (java.io.OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }

        private void handlePayTRWebhook(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, errorJson("Method not allowed"));
                return;
            }
            sendResponse(exchange, 200, "OK");
        }

        private String generateShopierHmacSignature(String data, String secret) {
            try {
                javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(
                        secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
                hmac.init(secretKeySpec);
                byte[] hash = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(hash);
            } catch (Exception e) {
                e.printStackTrace();
                return "";
            }
        }

    }

    private static void saveProductFile(int productId, String fileName, String base64Data) {
        if (fileName == null || base64Data == null || fileName.isEmpty() || base64Data.isEmpty())
            return;
        try {
            byte[] data = java.util.Base64.getDecoder().decode(base64Data);
            java.io.File uploadsDir = new java.io.File("uploads");
            if (!uploadsDir.exists())
                uploadsDir.mkdirs();

            // Sanitize filename
            String safeName = productId + "_" + fileName.replaceAll("[^a-zA-Z0-9.-]", "_");
            java.io.File file = new java.io.File(uploadsDir, safeName);

            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                fos.write(data);
            }

            db.setProductFile(productId, file.getAbsolutePath(), fileName);
            System.out.println("[LicenseServer] Saved file for product " + productId + ": " + safeName);
        } catch (Exception e) {
            System.err.println("[LicenseServer] Failed to save product file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean isRateLimited(String key, int limit, long window) {
        requestCounts.putIfAbsent(key, new java.util.concurrent.CopyOnWriteArrayList<>());
        List<Long> timestamps = requestCounts.get(key);

        long now = System.currentTimeMillis();
        // Remove expired entries
        timestamps.removeIf(timestamp -> now - timestamp > window);

        if (timestamps.size() >= limit) {
            return true;
        }

        timestamps.add(now);
        return false;
    }
}
