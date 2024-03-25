package shared;

import java.text.NumberFormat;

public class CurrencyFormatter {
    public static String real(final double amount) {
        final var currencyFormat = NumberFormat.getCurrencyInstance();
        return currencyFormat.format(amount);
    }
}
