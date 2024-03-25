package server.domain;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Bank {
    private static Map<String, CheckingAccount> accounts;

    public Bank() {
        accounts = new HashMap<String, CheckingAccount>();
        createCheckingAccount(
                "123456578",
                "Manuel Carlos",
                "Mossoró, rua da ufersa",
                "8499654785",
                "123548",
                "perucadojair");
        createCheckingAccount(
                "8454712156",
                "Noah Brutos",
                "Mossoró, rua do bar alto",
                "84996544512",
                "568214",
                "flamengo2002");
        createCheckingAccount(
                "123456578",
                "Manuel Carlos",
                "Mossoró, rua da ufersa",
                "8499654785",
                "123548",
                "perucadojair");

    }

    public boolean login(final String accountNumber, final String password) {
        final var checkingAccount = accounts.get(accountNumber);
        if (Objects.isNull(checkingAccount)) {
            System.out.println("usuário não existe.");
            return Boolean.FALSE;
        }
        if (accountNumber.equals(checkingAccount.getAccountNumber()) &&
                password.equals(checkingAccount.getPassword())) {
            System.out.println("usuário permitido.");
            return Boolean.TRUE;
        }
        System.out.println("usuário não permitido.");
        return Boolean.FALSE;
    }

    public boolean transfer(final String accountNumberRecipient, final double value) {
        final var checkingAccount = accounts.get(accountNumberRecipient);
        if (Objects.isNull(checkingAccount)) {
            System.out.println("conta não existe.");
            return Boolean.FALSE;
        }
        checkingAccount.transfer(checkingAccount, value);
        return Boolean.TRUE;
    }

    private void createCheckingAccount(
            final String CPF, final String customerName, final String address,
            final String phoneNumber, final String accountNumber, final String password) {
        final var checkingAccount = new CheckingAccount(CPF, customerName, address, phoneNumber,
                accountNumber, password);
        checkingAccount.setBalance(250);
        accounts.put(checkingAccount.getAccountNumber(), checkingAccount);
    }

    public CheckingAccount getCheckingAccount(final String accountNumber) {
        return accounts.get(accountNumber);
    }
}