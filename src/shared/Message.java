package shared;

import java.io.Serial;
import java.io.Serializable;

public class Message implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final MessageTypes type;
    private final String content;
    private final String HMAC;
    private final String authenticationKey;

    public Message(MessageTypes type, String content, String hMAC, String authenticationKey) {
        this.type = type;
        this.content = content;
        this.HMAC = hMAC;
        this.authenticationKey = authenticationKey;
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

}