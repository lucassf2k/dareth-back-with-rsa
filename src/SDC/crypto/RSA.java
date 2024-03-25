package SDC.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;

    public void generateKeys(final int keySize) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(keySize / 2, random);
        BigInteger q = BigInteger.probablePrime(keySize / 2, random);
        modulus = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        publicKey = BigInteger.probablePrime(keySize / 4, random); // Public exponent
        privateKey = publicKey.modInverse(phi);
    }
    public static String sign(
            final String message,
            final BigInteger privateKey,
            final BigInteger modulus
    ) {
        StringBuilder encrypted_message = new StringBuilder();
        for (char ch : message.toCharArray()) {
            BigInteger m = new BigInteger(Integer.toString(ch));
            BigInteger c = m.modPow(privateKey, modulus);
            encrypted_message.append(c).append(" ");
        }
        return encrypted_message.toString();
//        final var originalMessage = new BigInteger(message);
//        return originalMessage.modPow(privateKey, modulus).toString();
    }

    public static String checkSignature(
            final String encryptedMessage,
            final BigInteger publicKey,
            final BigInteger modulus
    ) {
        StringBuilder decryptedMessage = new StringBuilder();
        String[] chars = encryptedMessage.split(" ");
        for (final var ch : chars) {
            BigInteger c = new BigInteger(ch);
            BigInteger m = c.modPow(publicKey, modulus);
            final var v = (char)(m.intValue());
            decryptedMessage.append(v);
        }
        return decryptedMessage.toString();
//        final var message = new BigInteger(encryptedMessage.getBytes());
//        return new String(message.modPow(publicKey, modulus).toByteArray());
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
    public BigInteger getModulus() {
        return modulus;
    }

    public static void main(String[] args) {
        final RSA rsa = new RSA();
        final String plaintext = "111";
        rsa.generateKeys(1024);
        System.out.println("Chave publica: " + rsa.getPublicKey());
        System.out.println("Chave privada: " + rsa.getPrivateKey());
        final String encrypted = RSA.sign(plaintext, rsa.getPrivateKey(), rsa.getModulus());
        final String decrypted = RSA.checkSignature(encrypted, rsa.getPublicKey(), rsa.getModulus());
        System.out.println("Original: " + plaintext);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}