package SDC.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Keys {
    public static SecretKey generateAESKey() {
        KeyGenerator keyGenerator;
        SecretKey key = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return key;
    }

    public static String generateRandomBytes(final int size) {
        final var randomBytes = new byte[size];
        final var secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomBytes);
        return bytesToHex(randomBytes);
    }

    private static String bytesToHex(final byte[] bytes) {
        final var hexStringBuilder = new StringBuilder();
        for (var b : bytes) {
            hexStringBuilder.append(String.format("%02X", b));
        }
        return hexStringBuilder.toString();
    }
}
