package dev.barron.license;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * Secure License Client for Server-Side Key Storage
 * 
 * Uses ECDH key exchange with one-way encrypted channel.
 * Keys are never stored locally - always fetched from server.
 * 
 * Security:
 * - ECDH P-384 for key exchange
 * - AES-256-GCM for encryption
 * - Challenge-response authentication
 * - Anti-replay with nonce
 */
public class LicenseClient {

    private static final String CURVE = "secp384r1";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final String serverUrl;
    private final String licenseKey;
    private KeyPair clientKeyPair;
    private byte[] sharedSecret;

    public LicenseClient(String serverUrl, String licenseKey) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.licenseKey = licenseKey;
    }

    /**
     * Initialize secure connection and fetch encryption keys
     */
    public LicenseKeyBundle fetchKeys(String jarIdentifier) throws Exception {
        // Step 1: Generate ECDH key pair
        clientKeyPair = generateECDHKeyPair();
        byte[] clientPublicKey = clientKeyPair.getPublic().getEncoded();

        // Step 2: Send handshake request
        HandshakeResponse handshake = sendHandshake(clientPublicKey);

        // Step 3: Derive shared secret
        sharedSecret = deriveSharedSecret(
                clientKeyPair.getPrivate(),
                handshake.serverPublicKey);

        // Step 4: Solve challenge
        byte[] challengeResponse = solveChallenge(handshake.challenge, sharedSecret);

        // Step 5: Request encrypted keys
        byte[] encryptedKeys = requestKeys(handshake.sessionId, challengeResponse, jarIdentifier);

        // Step 6: Decrypt keys
        return decryptKeyBundle(encryptedKeys);
    }

    /**
     * Generate ECDH key pair
     */
    private KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * Send handshake to server
     */
    private HandshakeResponse sendHandshake(byte[] clientPublicKey) throws Exception {
        URL url = new URL(serverUrl + "api/handshake");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("X-License-Key", licenseKey);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(30000);

        // Send client public key
        String json = "{\"publicKey\":\"" + Base64.getEncoder().encodeToString(clientPublicKey) + "\"}";
        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            throw new LicenseException("Handshake failed: " + conn.getResponseMessage());
        }

        // Parse response
        String response = readResponse(conn);
        return parseHandshakeResponse(response);
    }

    /**
     * Derive shared secret using ECDH
     */
    private byte[] deriveSharedSecret(PrivateKey privateKey, byte[] serverPublicKeyBytes) throws Exception {
        // Reconstruct server public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(serverPublicKeyBytes);
        PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);

        // Perform ECDH
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(serverPublicKey, true);

        // Derive 256-bit key from shared secret
        byte[] secret = keyAgreement.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(secret);
    }

    /**
     * Solve server challenge
     */
    private byte[] solveChallenge(byte[] challenge, byte[] secret) throws Exception {
        // HMAC-SHA256 of challenge with shared secret
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret, "HmacSHA256");
        hmac.init(keySpec);
        return hmac.doFinal(challenge);
    }

    /**
     * Request encrypted keys from server
     */
    private byte[] requestKeys(String sessionId, byte[] challengeResponse, String jarIdentifier)
            throws Exception {
        URL url = new URL(serverUrl + "api/keys");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("X-License-Key", licenseKey);
        conn.setRequestProperty("X-Session-Id", sessionId);

        String json = String.format(
                "{\"challengeResponse\":\"%s\",\"jarIdentifier\":\"%s\"}",
                Base64.getEncoder().encodeToString(challengeResponse),
                jarIdentifier);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            throw new LicenseException("Key request failed: " + conn.getResponseMessage());
        }

        // Read encrypted keys
        String response = readResponse(conn);
        return Base64.getDecoder().decode(extractJsonValue(response, "encryptedKeys"));
    }

    /**
     * Decrypt key bundle
     */
    private LicenseKeyBundle decryptKeyBundle(byte[] encryptedData) throws Exception {
        // Extract IV (first 12 bytes)
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Decrypt with AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        byte[] decryptedData = cipher.doFinal(ciphertext);
        return LicenseKeyBundle.fromBytes(decryptedData);
    }

    private String readResponse(HttpURLConnection conn) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    private HandshakeResponse parseHandshakeResponse(String json) {
        HandshakeResponse response = new HandshakeResponse();
        response.serverPublicKey = Base64.getDecoder().decode(extractJsonValue(json, "serverPublicKey"));
        response.challenge = Base64.getDecoder().decode(extractJsonValue(json, "challenge"));
        response.sessionId = extractJsonValue(json, "sessionId");
        return response;
    }

    private String extractJsonValue(String json, String key) {
        int keyIndex = json.indexOf("\"" + key + "\"");
        if (keyIndex == -1)
            return "";
        int valueStart = json.indexOf("\"", keyIndex + key.length() + 3) + 1;
        int valueEnd = json.indexOf("\"", valueStart);
        return json.substring(valueStart, valueEnd);
    }

    private static class HandshakeResponse {
        byte[] serverPublicKey;
        byte[] challenge;
        String sessionId;
    }

    public static class LicenseException extends Exception {
        public LicenseException(String message) {
            super(message);
        }
    }
}
