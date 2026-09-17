package securevault.util;

import java.io.Console;
import java.io.InputStream;
import java.util.NoSuchElementException;
import java.util.Scanner;

/**
 * Robust input reader utility providing validation, visual asterisk password masking,
 * and crash-resistant user interaction.
 */
public class InputHelper {
    private final Scanner scanner;

    public InputHelper() {
        this(System.in);
    }

    public InputHelper(InputStream in) {
        this.scanner = new Scanner(in);
    }

    public InputHelper(Scanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Reads a non-empty string input.
     */
    public String readNonEmptyString(String prompt) {
        while (true) {
            System.out.print(prompt);
            if (!scanner.hasNextLine()) {
                throw new NoSuchElementException("End of input stream reached.");
            }
            String input = scanner.nextLine();
            if (input != null && !input.trim().isEmpty()) {
                return input.trim();
            }
            System.out.println("Error: Input cannot be empty. Please try again.");
        }
    }

    /**
     * Reads a line of string input (can be empty, e.g. for optional notes or leaving unchanged).
     */
    public String readString(String prompt) {
        System.out.print(prompt);
        if (!scanner.hasNextLine()) {
            return "";
        }
        String input = scanner.nextLine();
        return input != null ? input.trim() : "";
    }

    /**
     * Reads a password securely. Uses System.console().readPassword() when available,
     * and automatically replaces the entered input line with visual asterisks (*****).
     */
    public char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            while (true) {
                char[] pass = console.readPassword(prompt);
                if (pass != null && pass.length > 0) {
                    StringBuilder stars = new StringBuilder();
                    for (int i = 0; i < pass.length; i++) {
                        stars.append('*');
                    }
                    // Overwrite prompt line with asterisks
                    System.out.print("\033[1A\r\033[2K" + prompt + stars + "\n");
                    return pass;
                }
                System.out.println("Error: Password cannot be empty. Please try again.");
            }
        } else {
            // Fallback for IDE internal consoles / VS Code runner
            while (true) {
                System.out.print(prompt);
                if (!scanner.hasNextLine()) {
                    throw new NoSuchElementException("End of input stream reached.");
                }
                String line = scanner.nextLine();
                if (line != null && !line.trim().isEmpty()) {
                    StringBuilder stars = new StringBuilder();
                    for (int i = 0; i < line.length(); i++) {
                        stars.append('*');
                    }
                    // Erase typed plain text and replace with asterisks
                    System.out.print("\033[1A\r\033[2K" + prompt + stars + "\n");
                    return line.toCharArray();
                }
                System.out.println("Error: Password cannot be empty. Please try again.");
            }
        }
    }

    /**
     * Reads an integer within [min, max] range.
     */
    public int readInt(String prompt, int min, int max) {
        while (true) {
            System.out.print(prompt);
            if (!scanner.hasNextLine()) {
                throw new NoSuchElementException("End of input stream reached.");
            }
            String line = scanner.nextLine();
            try {
                int value = Integer.parseInt(line.trim());
                if (value >= min && value <= max) {
                    return value;
                }
                System.out.printf("Error: Please enter a number between %d and %d.%n", min, max);
            } catch (NumberFormatException e) {
                System.out.println("Error: Invalid number. Please enter a valid numeric value.");
            }
        }
    }

    /**
     * Reads a positive integer (e.g. Account ID).
     */
    public int readAccountId(String prompt) {
        while (true) {
            System.out.print(prompt);
            if (!scanner.hasNextLine()) {
                throw new NoSuchElementException("End of input stream reached.");
            }
            String line = scanner.nextLine();
            try {
                int value = Integer.parseInt(line.trim());
                if (value > 0) {
                    return value;
                }
                System.out.println("Error: Account ID must be a positive number.");
            } catch (NumberFormatException e) {
                System.out.println("Error: Invalid ID. Please enter a numeric account ID.");
            }
        }
    }

    /**
     * Reads a Yes/No confirmation (Y/N).
     */
    public boolean readYesNo(String prompt) {
        while (true) {
            System.out.print(prompt);
            if (!scanner.hasNextLine()) {
                throw new NoSuchElementException("End of input stream reached.");
            }
            String input = scanner.nextLine();
            if (input != null) {
                String trimmed = input.trim().toLowerCase();
                if (trimmed.equals("y") || trimmed.equals("yes")) {
                    return true;
                }
                if (trimmed.equals("n") || trimmed.equals("no")) {
                    return false;
                }
            }
            System.out.println("Error: Please enter 'Y' for Yes or 'N' for No.");
        }
    }

    /**
     * Prompts the user to press Enter to continue.
     */
    public void pressEnterToContinue() {
        System.out.print("\nPress Enter to continue...");
        try {
            if (scanner.hasNextLine()) {
                scanner.nextLine();
            }
        } catch (Exception ignored) {}
    }
}
