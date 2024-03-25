package SDC;

import SDC.crypto.RSA;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.Serializable;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SDCService implements Protocol {
    public static final int PORT = 5006;

    @Override
    public String getAESKey() throws RemoteException {
        return this.generateAESKey().toString();
    }

    @Override
    public RSAKeys getRSAKeys() throws RemoteException {
        final var rsa = new RSA();
        rsa.generateKeys(1024);
        return new RSAKeys(rsa.getPublicKey(), rsa.getPrivateKey(), rsa.getModulus());
    }

    @Override
    public String getVernamKey() throws RemoteException {
        return generateRandomBytes(128);
    }

    private SecretKey generateAESKey() {
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

    private String generateRandomBytes(final int size) {
        final var randomBytes = new byte[size];
        final var secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomBytes);
        return bytesToHex(randomBytes);
    }

    private String bytesToHex(final byte[] bytes) {
        final var hexStringBuilder = new StringBuilder();
        for (var b : bytes) {
            hexStringBuilder.append(String.format("%02X", b));
        }
        return hexStringBuilder.toString();
    }


    public record RSAKeys(BigInteger publicKey, BigInteger privateKey, BigInteger modulus) implements Serializable {}
}
