package dev.barron.utils;

import com.google.common.io.BaseEncoding;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpUtil {

    private static final int SECRET_SIZE = 10;
    private static final int WINDOW_SIZE = 3; // 3 windows of 30 seconds (allow slightly earlier/later codes)

    public static String generateSecret() {
        byte[] buffer = new byte[SECRET_SIZE];
        new SecureRandom().nextBytes(buffer);
        return BaseEncoding.base32().encode(buffer);
    }

    public static String getQrCodeUrl(String label, String issuer, String secret) {
        try {
            String uri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                    URLEncoder.encode(label, StandardCharsets.UTF_8),
                    secret,
                    URLEncoder.encode(issuer, StandardCharsets.UTF_8));
            return "https://quickchart.io/chart?cht=qr&chs=200x200&chl="
                    + URLEncoder.encode(uri, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static boolean verifyCode(String secret, int code) {
        BaseEncoding base32 = BaseEncoding.base32();
        byte[] decodedKey = base32.decode(secret);
        long timeWindow = System.currentTimeMillis() / 1000 / 30;

        for (int i = -1; i <= 1; i++) {
            long hash = generateTOTP(decodedKey, timeWindow + i);
            if (hash == code) {
                return true;
            }
        }
        return false;
    }

    private static long generateTOTP(byte[] key, long time) {
        byte[] data = new byte[8];
        long value = time;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;

            long truncatedHash = 0;
            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= 1000000;

            return truncatedHash;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return -1;
        }
    }
}
