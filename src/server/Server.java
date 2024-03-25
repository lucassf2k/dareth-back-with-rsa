package server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
    private int port;

    public Server(final int port) {
        this.port = port;
        exec();
    }

    @SuppressWarnings("resource")
    private void exec() {
        try {
            final var serverSocker = new ServerSocket(this.port);
            System.out.println("aguardando conexão com cliente...");
            while (true) {
                final var client = serverSocker.accept();
                final var handler = new ServerHandler(client);
                final var tServer = new Thread(handler);
                tServer.start();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        new Server(56001);
    }
}