package client;

import java.io.IOException;
import java.net.Socket;

import javax.crypto.SecretKey;

public class Client {
    private final String ip;
    public static String KEY_HMAC;
    public static String KEY_VERNAM;
    public static SecretKey KEY_AES;
    private final int port;

    public Client(final String ip, final int port) {
        this.ip = ip;
        this.port = port;
        exec();
    }

    private void exec() {
        try {
            final var socket = new Socket(this.ip, this.port);
            final var handler = new ClientHandler(socket);
            final var tClient = new Thread(handler);
            tClient.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        new Client("127.0.0.1", 56001);
    }
}