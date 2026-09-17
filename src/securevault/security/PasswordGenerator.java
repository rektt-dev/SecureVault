package securevault.security;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Cryptographically secure password generator using SecureRandom.
 * Supports customizable character sets, lengths, and entropy guarantees.
 */
public class PasswordGenerator {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    public static final int MIN_LENGTH = 6;
    public static final int MAX_LENGTH = 128;
    public static final int DEFAULT_LENGTH = 16;

    private final SecureRandom secureRandom;

    public PasswordGenerator() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a random password based on length and character set preferences.
     *
     * @param length Desired password length
     * @param useUpper Include uppercase letters
     * @param useLower Include lowercase letters
     * @param useDigits Include digits
     * @param useSymbols Include symbols
     * @return Generated password string
     */
    public String generatePassword(int length, boolean useUpper, boolean useLower, boolean useDigits, boolean useSymbols) {
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException(String.format("Password length must be between %d and %d.", MIN_LENGTH, MAX_LENGTH));
        }

        StringBuilder allowedChars = new StringBuilder();
        List<Character> mandatoryChars = new ArrayList<>();

        if (useUpper) {
            allowedChars.append(UPPERCASE);
            mandatoryChars.add(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
        }
        if (useLower) {
            allowedChars.append(LOWERCASE);
            mandatoryChars.add(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
        }
        if (useDigits) {
            allowedChars.append(DIGITS);
            mandatoryChars.add(DIGITS.charAt(secureRandom.nextInt(DIGITS.length())));
        }
        if (useSymbols) {
            allowedChars.append(SYMBOLS);
            mandatoryChars.add(SYMBOLS.charAt(secureRandom.nextInt(SYMBOLS.length())));
        }

        if (allowedChars.length() == 0) {
            throw new IllegalArgumentException("At least one character type must be selected.");
        }

        List<Character> passwordChars = new ArrayList<>(mandatoryChars);
        String pool = allowedChars.toString();

        // Fill remaining slots
        while (passwordChars.size() < length) {
            passwordChars.add(pool.charAt(secureRandom.nextInt(pool.length())));
        }

        // Secure Fisher-Yates shuffle
        Collections.shuffle(passwordChars, secureRandom);

        StringBuilder result = new StringBuilder(passwordChars.size());
        for (char c : passwordChars) {
            result.append(c);
        }

        return result.toString();
    }

    /**
     * Generates a default strong 16-character password with all character sets.
     */
    public String generateDefault() {
        return generatePassword(DEFAULT_LENGTH, true, true, true, true);
    }
}
