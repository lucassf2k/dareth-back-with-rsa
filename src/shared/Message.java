package shared;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;

public class Message implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final MessageTypes type;
    private final String content;
    private final String HMAC;
    private final String authenticationKey;
    private final BigInteger clientPublicKey;
    private final BigInteger clientModulus;

    public Message(
            MessageTypes type,
            String content,
            String hMAC,
            String authenticationKey,
            BigInteger clientPublicKey,
            BigInteger clientModulus
    ) {
        this.type = type;
        this.content = content;
        this.HMAC = hMAC;
        this.authenticationKey = authenticationKey;
        this.clientPublicKey = clientPublicKey;
        this.clientModulus = clientModulus;
    }

    public MessageTypes getType() {
        return type;
    }

    public String getHMAC() {
        return HMAC;
    }

    public String getContent() {
        return content;
    }

    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    public String getAuthenticationKey() {
        return authenticationKey;
    }

    public BigInteger getClientPublicKey() {
        return clientPublicKey;
    }

    public BigInteger getClientModulus() {
        return clientModulus;
    }
}