package server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import SDC.Protocol;
import SDC.SDCService;
import SDC.crypto.RSA;
import client.ClientHandler;
import server.domain.Bank;
import server.domain.CheckingAccount;
import shared.CurrencyFormatter;
import shared.FileService;
import shared.Message;
import shared.MessageTypes;
import SDC.crypto.AES128;
import SDC.crypto.HMAC;
import SDC.crypto.Vernam;

public class ServerHandler implements Runnable {
    private final Socket client;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private static Bank bank;
    private int response = 1;
    private CheckingAccount currentCheckingAccount = null;
    private String authenticationKey;
    private SDCService.RSAKeys serverRsaKeys;
    private final Protocol SDCStub;

    public ServerHandler(Socket client) {
        try {
            this.client = client;
            final var registrySDC = LocateRegistry.getRegistry(SDCService.PORT);
            SDCStub = (Protocol) registrySDC.lookup("sdc");
            serverRsaKeys = SDCStub.getRSAKeys();
            bank = new Bank();
        } catch (RemoteException | NotBoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        System.out.println("conectando com o cliente...");
        try {
            output = new ObjectOutputStream(client.getOutputStream());
            input = new ObjectInputStream(client.getInputStream());
            boolean hasConnection = Boolean.TRUE;
            while (hasConnection) {
                final var request = (Message) input.readObject();
                if (request.getType().equals(MessageTypes.LOGIN)) {
                    authentication(request);
                    continue;
                }
                if (request.getType().equals(MessageTypes.WITHDRAW)) {
                    withdraw(request);
                    continue;
                }
                if (request.getType().equals(MessageTypes.GET_BALANCE)) {
                    getBalance();
                    continue;
                }
                if (request.getType().equals(MessageTypes.DEPOSIT)) {
                    deposit(request);
                    continue;
                }
                if (request.getType().equals(MessageTypes.TRANSFER)) {
                    transfer(request);
                    continue;
                }
                if (request.getType().equals(MessageTypes.INVESTMENT)) {
                    investment(request);
                    continue;
                }
            }
            input.close();
            output.close();
            client.close();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private void authentication(final Message request) {
        System.out.println("autenticando...");
        final var isAuthenticated = checkMessageAuthenticity(request.getContent(), request.getHMAC());
        System.out.println(isAuthenticated);
        System.out.println("descriptando mensagem...");
        final var vernamMessageDecrypted = decrypt(request);
        final var splitedMessage = vernamMessageDecrypted.split("-");
        final var accountNumber = splitedMessage[0];
        final var password = splitedMessage[1];
        System.out.println("Ac: " + accountNumber);
        System.out.println("PAS: " + password);
        final var isRegistered = bank.login(accountNumber, password);
        if (isAuthenticated && isRegistered) {
            response = 2;
            currentCheckingAccount = bank.getCheckingAccount(accountNumber);
        }
        System.out.println(isRegistered);
        final var keys = getKeys();
        try {
            final var userExists = bank.getCheckingAccount(accountNumber);
            if (!Objects.isNull(userExists)) {
                authenticationKey = HMAC.hMac(keys[1], accountNumber);
                output.writeUTF(authenticationKey);
                output.writeInt(response);
                output.flush();
            } else {
                output.writeUTF("Não está cadastrado.");
                output.writeInt(response);
                output.flush();
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void withdraw(final Message request) {
        System.out.println("descriptografando a mensagem...");
        try {
            final var authenticationKeyClient = request.getAuthenticationKey();
            final var isAuthenticated = checkMessageAuthenticity(request.getContent(), request.getHMAC());
            if (!isAuthenticated) {
                response = 1;
                output.writeUTF("credencias incorretas");
                output.writeInt(response);
                output.flush();
                return;
            }
            if (!authenticationKey.equals(authenticationKeyClient)) {
                response = 1;
                System.out.println("sem chave autenticada.");
                output.writeInt(response);
                output.flush();
                return;
            }
            final var decryptedMessage = decrypt(request);
            System.out.println(decryptedMessage);
            currentCheckingAccount.withdraw(Double.valueOf(decryptedMessage));
            output.writeInt(response);
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getBalance() {
        try {
            output.writeUTF("seu saldo é de " + CurrencyFormatter.real(currentCheckingAccount.getBalance()));
            output.writeInt(response);
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void deposit(final Message request) {
        System.out.println("verificando se é uma mensagem autentica...");
        final var isAuthenticated = checkMessageAuthenticity(request.getContent(), request.getHMAC());
        System.out.println("mensagem eutêntica.");
        if (!isAuthenticated) {
            response = 1;
        }
        final var decryptedMessage = decrypt(request);
        currentCheckingAccount.deposit(Double.valueOf(decryptedMessage));
        try {
            output.writeInt(response);
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void transfer(final Message request) {
        System.out.println("verificando se é uma mensagem autêntica...");
        final var isAutehnticated = checkMessageAuthenticity(request.getContent(), request.getHMAC());
        if (!isAutehnticated) {
            response = 1;
        }
        System.out.println("mensagem autêntica.");
        final var decryptedMessage = decrypt(request);
        final var splitedDecryptedMessage = decryptedMessage.split("-");
        final var accountNumberRecipient = splitedDecryptedMessage[0];
        final var value = splitedDecryptedMessage[1];
        final var checkingAccountRecipient = bank.getCheckingAccount(accountNumberRecipient);
        currentCheckingAccount.transfer(checkingAccountRecipient, Double.valueOf(value));
        try {
            output.writeUTF("tranferência realizada com sucesso.");
            output.writeInt(response);
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void investment(final Message request) {
        System.out.println("verificando se é uma mensagem autenticada");
        final var authenticationKeyClient = request.getAuthenticationKey();
        final var isAuthenticated = checkMessageAuthenticity(request.getContent(), request.getHMAC());
        try {
            if (!isAuthenticated) {
                response = 1;
                output.writeUTF("mensagem não autentica.");
                output.writeInt(response);
                output.flush();
                return;
            }
            if (!authenticationKey.equals(authenticationKeyClient)) {
                response = 1;
                System.out.println("sem chave autenticada.");
                output.writeInt(response);
                output.flush();
                return;
            }
            final var decryptedMessage = decrypt(request);
            double balanceTreeMonths = 0.0;
            double balanceSixMonths = 0.0;
            double balanceTwelveMonths = 0.0;
            double balance = currentCheckingAccount.getBalance();
            if (Integer.valueOf(decryptedMessage) == 1) {
                for (var month = 1; month <= 12; month++) {
                    balance += (balance * 0.005);
                    if (month == 3)
                        balanceTreeMonths = balance;
                    if (month == 6)
                        balanceSixMonths = balance;
                    if (month == 12)
                        balanceTwelveMonths = balance;
                }
            }
            if (Integer.valueOf(decryptedMessage) == 2) {
                for (var month = 1; month <= 12; month++) {
                    balance += (balance * 0.015);
                    if (month == 3)
                        balanceTreeMonths = balance;
                    if (month == 6)
                        balanceSixMonths = balance;
                    if (month == 12)
                        balanceTwelveMonths = balance;
                }
            }
            output.writeUTF("Em 3 meses: " + CurrencyFormatter.real(balanceTreeMonths));
            output.writeUTF("Em 6 meses: " + CurrencyFormatter.real(balanceSixMonths));
            output.writeUTF("Em 1 ano: " + CurrencyFormatter.real(balanceTwelveMonths));
            output.writeInt(response);
            output.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String decrypt(final Message request) {
        final var keys = getKeys();
        String decryptedMessage;
        try {
            final var AESMessageDecrypted = AES128.decrypt(request.getContent(), AES128.stringToSecretKey(keys[2]));
            decryptedMessage = Vernam.decrypt(AESMessageDecrypted, keys[0]);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return decryptedMessage;
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

    private boolean checkMessageAuthenticity(final String encryptedMessage, final String HMACMessage) {
        try {
            final var keys = getKeys();
            final var hmacMessage = RSA.checkSignature(
                    HMACMessage,
                    new BigInteger(keys[3]),
                    new BigInteger(keys[4]));
            System.out.println(new BigInteger(keys[3]));
            System.out.println(keys[4]);
            System.out.println(HMACMessage);
            System.out.println("VERI: " + hmacMessage);
            final var HMACCompare = HMAC.hMac(keys[1], encryptedMessage);
            System.out.println(HMACCompare);
            if (hmacMessage.equals(HMACCompare)) {
                return Boolean.TRUE;
            }
            return Boolean.FALSE;
        } catch (InvalidKeyException | NoSuchAlgorithmException
                 | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}