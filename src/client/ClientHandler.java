package client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import SDC.Protocol;
import SDC.SDCService;
import SDC.crypto.*;
import server.ServerHandler;
import shared.FileService;
import shared.Message;
import shared.MessageTypes;

public class ClientHandler implements Runnable {
    private int hasRequest = 1;
    private final Socket client;
    private ObjectInputStream input;
    private ObjectOutputStream output;
    private String authenticationKey;
    private final Scanner scan = new Scanner(System.in);
    public static int PORT;
    private SDCService.RSAKeys clientRsaKeys;
    public BigInteger clientPublicKey;
    public BigInteger clientMudulus;
    private BigInteger clientPrivateKey;
    private final Protocol SDCStub;

    public ClientHandler(final Socket client) {
        this.client = Objects.requireNonNull(client, "O socket do cliente não pode ser nulo.");
        try {
            final var registrySDC = LocateRegistry.getRegistry(SDCService.PORT);
            SDCStub = (Protocol) registrySDC.lookup("sdc");
            clientRsaKeys = SDCStub.getRSAKeys();
            clientPrivateKey = clientRsaKeys.privateKey();
            clientPublicKey = clientRsaKeys.publicKey();
            clientMudulus = clientRsaKeys.modulus();
        } catch (RemoteException | NotBoundException e) {
            throw new RuntimeException(e);
        }
        PORT = this.client.getPort();
    }

    @Override
    public void run() {
        System.out.println("cliente conectou ao servidor.");
        try {
            output = new ObjectOutputStream(client.getOutputStream());
            input = new ObjectInputStream(client.getInputStream());
            boolean hasConnection = Boolean.TRUE;
            while (hasConnection) {
                welcome();
                while (hasRequest != 0) {
                    switch (hasRequest) {
                        case 1:
                            login();
                            break;
                        case 2:
                            menu();
                            break;
                        default:
                            break;
                    }
                }
            }
            output.close();
            client.close();
            System.out.println("cliente finalizando conexão...");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String makeMessageSecure(final String message, final String vernamKey, final String AESKey) {
        try {
            final var vernamMessage = Vernam.encrypt(message, vernamKey);
            return AES128.encrypt(vernamMessage, AES128.stringToSecretKey(AESKey));
        } catch (
                InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private void sendMessage(final Message request) {
        try {
            output.writeObject(request);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void welcome() {
        System.out.println("==== Bem vindo ao Dareth Bank ====");
        generateKeysFile();
    }

    private void generateKeysFile() {
        try {
            final var filename = "keys.txt";
            FileService.insert(SDCStub.getVernamKey(), filename);
            FileService.insert(SDCStub.getVernamKey(), filename);
            final var keyAESString = Base64.getEncoder().encodeToString(Keys.generateAESKey().getEncoded());
            FileService.insert(keyAESString, filename);
            final var rsaKeys = SDCStub.getRSAKeys();
            FileService.insert(rsaKeys.publicKey().toString(), filename);
            FileService.insert(rsaKeys.modulus().toString(), filename);
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    private void login() {
        System.out.println("== LOGIN == ");
        System.out.print("- Número: ");
        final var accountNumber = scan.nextLine();
        System.out.print("- Senha: ");
        final var password = scan.nextLine();
        final var message = accountNumber + "-" + password;
        final var keys = getKeys();
        final var secureMessage = makeMessageSecure(message, keys[0], keys[2]);
        try {
            final var HMACMessage = HMAC.hMac(keys[1], secureMessage);
            final var RSASignature = RSA.sign(
                    HMACMessage,
                    clientPrivateKey,
                    clientMudulus);
            final var request = new Message(
                    MessageTypes.LOGIN,
                    secureMessage,
                    RSASignature,
                    authenticationKey,
                    clientPublicKey,
                    clientMudulus
            );
            sendMessage(request);
            cleanTerminal();
            authenticationKey = input.readUTF();
            authenticationKey = "";
            hasRequest = input.readInt();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private String[] getKeys() {
        final var keys = FileService.get("keys.txt");
        final var splitedKeys = keys.split("\n");
        final var vernamKey = splitedKeys[0];
        final var HMACKey = splitedKeys[1];
        final var AESKey = splitedKeys[2];
        final var publicKeyRSA = splitedKeys[3];
        final var modulusRSA = splitedKeys[4];
        final var output = new String[splitedKeys.length];
        output[0] = vernamKey;
        output[1] = HMACKey;
        output[2] = AESKey;
        output[3] = publicKeyRSA;
        output[4] = modulusRSA;
        return output;
    }

    private void menu() {
        System.out.println("== O que quer fazer? ==");
        System.out.println("[1] - Sacar");
        System.out.println("[2] - Saldo");
        System.out.println("[3] - Depositar");
        System.out.println("[4] - Transferir");
        System.out.println("[5] - Simular investimento");
        System.out.print("Opção: ");
        final var result = scan.nextInt();
        switch (result) {
            case 1:
                withdraw();
                break;
            case 2:
                getBalance();
                break;
            case 3:
                deposit();
                break;
            case 4:
                transfer();
                break;
            case 5:
                investment();
                break;
            default:
                break;
        }
    }

    private void withdraw() {
        System.out.print("Digite o valor que quer retirar: ");
        final var value = scan.nextDouble();
        final var keys = getKeys();
        final var secureMessage = makeMessageSecure(String.valueOf(value), keys[0], keys[2]);
        try {
            final var HMACMessage = HMAC.hMac(keys[1], secureMessage);
            final var RSASignature = RSA.sign(
                    HMACMessage,
                    clientPrivateKey,
                    clientMudulus);
            final var request = new Message(
                    MessageTypes.WITHDRAW,
                    secureMessage,
                    RSASignature,
                    authenticationKey,
                    clientPublicKey,
                    clientMudulus
            );
            sendMessage(request);
            hasRequest = input.readInt();
            cleanTerminal();
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getBalance() {
        final var request = new Message(
                MessageTypes.GET_BALANCE,
                null,
                null, authenticationKey,
                clientPublicKey,
                clientMudulus
        );
        sendMessage(request);
        try {
            cleanTerminal();
            System.out.println(input.readUTF());
            hasRequest = input.readInt();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void deposit() {
        System.out.print("Digite o valor que deseja depositar: ");
        final var value = scan.nextDouble();
        final var keys = getKeys();
        final var secureMessage = makeMessageSecure(String.valueOf(value), keys[0], keys[2]);
        try {
            final var HMACMessage = HMAC.hMac(keys[1], secureMessage);
            final var RSASignature = RSA.sign(
                    HMACMessage,
                    clientPrivateKey,
                    clientMudulus);
            final var request = new Message(
                    MessageTypes.DEPOSIT,
                    secureMessage,
                    RSASignature,
                    authenticationKey,
                    clientPublicKey,
                    clientMudulus
            );
            sendMessage(request);
            cleanTerminal();
            hasRequest = input.readInt();
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void transfer() {
        System.out.print("Número da conta para qual quer tranferir: ");
        final var accountNumberRecipient = scan.nextInt();
        System.out.print("Valor da transferência: ");
        final var value = scan.nextDouble();
        final var keys = getKeys();
        final var message = accountNumberRecipient + "-" + value;
        final var secureMessage = makeMessageSecure(message, keys[0], keys[2]);
        try {
            final var HMACMessage = HMAC.hMac(keys[1], secureMessage);
            final var RSASignature = RSA.sign(
                    HMACMessage,
                    clientPrivateKey,
                   clientMudulus);
            final var request = new Message(
                    MessageTypes.TRANSFER,
                    secureMessage,
                    RSASignature,
                    authenticationKey,
                    clientPublicKey,
                    clientMudulus
            );
            sendMessage(request);
            cleanTerminal();
            System.out.println(input.readUTF());
            hasRequest = input.readInt();
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }

    }

    private void investment() {
        System.out.println("[1] - Poupança");
        System.out.println("[2] - Fixa");
        final var option = scan.nextInt();
        final var keys = getKeys();
        final var secureMessage = makeMessageSecure(String.valueOf(option), keys[0], keys[2]);
        try {
            final var HMACMessage = HMAC.hMac(keys[1], secureMessage);
            final var RSASignature = RSA.sign(
                    HMACMessage,
                    clientPrivateKey,
                    clientMudulus);
            final var request = new Message(
                    MessageTypes.INVESTMENT,
                    secureMessage,
                    RSASignature,
                    authenticationKey,
                    clientPublicKey,
                    clientMudulus
            );
            sendMessage(request);
            cleanTerminal();
            if (option == 1 || option == 2) {
                System.out.println(input.readUTF());
                System.out.println(input.readUTF());
                System.out.println(input.readUTF());
                hasRequest = input.readInt();
                return;
            }
            System.out.println(input.readUTF());
            hasRequest = input.readInt();
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void cleanTerminal() {
        try {
            // Verificar se o sistema operacional é Windows
            if (System.getProperty("os.name").startsWith("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                // Para sistemas Unix-like (Linux, macOS, etc.)
                System.out.print("\033[H\033[2J");
                System.out.flush();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}