package SDC.crypto;

public class Vernam {
    private Vernam() {
    }

    public static String encrypt(final String message, final String key) {
        final var result = new StringBuilder();
        for (var i = 0; i < message.length(); i++) {
            final var character = message.charAt(i);
            final var keyChar = key.charAt(i % key.length());
            final var encrypted = (char) (character ^ keyChar);
            result.append(encrypted);
        }
        return result.toString();
    }

    public static String decrypt(final String messageEncrypted, final String key) {
        return Vernam.encrypt(messageEncrypted, key);
    }
}
