package SDC.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AES128 {
    private static final String CIPHER_INPUT_INSTANCE = "AES/ECB/PKCS5Padding";

    public static SecretKey generateKeys() throws NoSuchAlgorithmException {
        final var keyGenerator = KeyGenerator.getInstance("AES");
        return keyGenerator.generateKey();
    }

    public static SecretKey stringToSecretKey(final String input) {
        byte[] decodedKey = Base64.getDecoder().decode(input);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static String encrypt(final String openText, final SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        final var cipher = Cipher.getInstance(AES128.CIPHER_INPUT_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final var bytesEncryptedMessage = cipher.doFinal(openText.getBytes());
        return Base64.getEncoder().encodeToString(bytesEncryptedMessage);
    }

    public static String decrypt(final String encryptedText, final SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        final var bytesEncryptedMessage = Base64.getDecoder().decode(encryptedText);
        final var cipher = Cipher.getInstance(AES128.CIPHER_INPUT_INSTANCE);
        cipher.init(Cipher.DECRYPT_MODE, key);
        final var bytesDecryptedMessage = cipher.doFinal(bytesEncryptedMessage);
        return new String(bytesDecryptedMessage);
    }
}