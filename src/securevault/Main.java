package securevault;

import securevault.manager.PasswordManager;
import securevault.model.PasswordEntry;
import securevault.security.AuthenticationManager;
import securevault.security.EncryptionManager;
import securevault.security.PasswordGenerator;
import securevault.security.PasswordStrengthChecker;
import securevault.storage.VaultStorage;
import securevault.util.ClipboardHelper;
import securevault.util.InputHelper;

import java.io.File;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Main entry point for SecureVault — Encrypted Password Manager.
 * Orchestrates CLI interactions, menus, and component lifecycles.
 */
public class Main {
    private static final String DEFAULT_VAULT_PATH = "data" + File.separator + "vault.dat";

    private final InputHelper input;
    private final EncryptionManager encryptionManager;
    private final VaultStorage vaultStorage;
    private final AuthenticationManager authManager;
    private final PasswordManager passwordManager;
    private final PasswordGenerator passwordGenerator;
    private final PasswordStrengthChecker strengthChecker;

    public Main() {
        this(DEFAULT_VAULT_PATH, new InputHelper());
    }

    public Main(InputHelper input) {
        this(DEFAULT_VAULT_PATH, input);
    }

    public Main(String vaultFilePath, InputHelper input) {
        this.input = input;
        this.encryptionManager = new EncryptionManager();
        this.vaultStorage = new VaultStorage(vaultFilePath, encryptionManager);
        this.authManager = new AuthenticationManager(vaultStorage);
        this.passwordManager = new PasswordManager();
        this.passwordGenerator = new PasswordGenerator();
        this.strengthChecker = new PasswordStrengthChecker();
    }

    public static void main(String[] args) {
        Main app = new Main();
        app.run();
    }

    public void run() {
        try {
            boolean running = true;
            while (running) {
                if (!authManager.isAuthenticated()) {
                    boolean authenticated = handleStartupAuthentication();
                    if (!authenticated) {
                        System.out.println("\nExiting SecureVault. Goodbye!");
                        break;
                    }
                }

                // Authenticated main menu loop
                running = handleMainMenu();
            }
        } catch (NoSuchElementException e) {
            System.out.println("\nSession ended. Exiting SecureVault.");
        }
    }

    /**
     * Handles initial screen: checks if vault exists, allows creation or unlock.
     */
    private boolean handleStartupAuthentication() {
        System.out.println("=============================================");
        System.out.println("            SECUREVAULT");
        System.out.println("     ENCRYPTED PASSWORD MANAGER");
        System.out.println("=============================================");

        if (!vaultStorage.vaultExists()) {
            System.out.println("No vault found.");
            System.out.println("1. Create New Vault");
            System.out.println("2. Exit");
            int choice = input.readInt("Enter choice: ", 1, 2);

            if (choice == 1) {
                return handleCreateVault();
            } else {
                return false;
            }
        } else {
            return handleUnlockVault();
        }
    }

    /**
     * First-time vault creation wizard.
     */
    private boolean handleCreateVault() {
        System.out.println("\n=============================================");
        System.out.println("             CREATE NEW VAULT");
        System.out.println("=============================================");

        while (true) {
            char[] pass1 = input.readPassword("Create Master Password: ");
            char[] pass2 = input.readPassword("Confirm Master Password: ");

            if (!Arrays.equals(pass1, pass2)) {
                System.out.println("Error: Passwords do not match. Please try again.\n");
                Arrays.fill(pass1, '\0');
                Arrays.fill(pass2, '\0');
                continue;
            }

            if (pass1.length < 6) {
                System.out.println("Error: Master password must be at least 6 characters long.\n");
                Arrays.fill(pass1, '\0');
                Arrays.fill(pass2, '\0');
                continue;
            }

            String passStr = new String(pass1);
            PasswordStrengthChecker.EvaluationResult result = strengthChecker.evaluate(passStr);
            System.out.println("Password Strength: " + result.level.getLabel());

            boolean confirm = input.readYesNo("Create vault? (Y/N): ");
            if (confirm) {
                try {
                    vaultStorage.createNewVault(pass1);
                    authManager.establishSession(pass1);
                    passwordManager.clear();
                    System.out.println("\nVault created successfully.");
                    input.pressEnterToContinue();
                    return true;
                } catch (Exception e) {
                    System.out.println("Error creating vault: " + e.getMessage());
                    return false;
                } finally {
                    Arrays.fill(pass1, '\0');
                    Arrays.fill(pass2, '\0');
                }
            } else {
                Arrays.fill(pass1, '\0');
                Arrays.fill(pass2, '\0');
                System.out.println("Vault creation cancelled.");
                return false;
            }
        }
    }

    /**
     * Prompts for master password and decrypts vault.
     */
    private boolean handleUnlockVault() {
        int maxAttempts = 3;
        int attempts = 0;

        while (attempts < maxAttempts) {
            char[] masterPassword = input.readPassword("Enter Master Password: ");
            try {
                List<PasswordEntry> entries = authManager.authenticate(masterPassword);
                passwordManager.setEntries(entries);
                System.out.println("\nAccess granted.");
                return true;
            } catch (GeneralSecurityException e) {
                attempts++;
                System.out.println("\nIncorrect master password or corrupted vault.");
                if (attempts < maxAttempts) {
                    System.out.printf("Attempts remaining: %d%n%n", (maxAttempts - attempts));
                }
            } catch (Exception e) {
                System.out.println("\nUnable to load vault: " + e.getMessage());
                return false;
            } finally {
                Arrays.fill(masterPassword, '\0');
            }
        }

        System.out.println("Maximum authentication attempts exceeded.");
        return false;
    }

    /**
     * Main authenticated menu loop.
     */
    private boolean handleMainMenu() {
        System.out.println("\n=============================================");
        System.out.println("                 SECUREVAULT");
        System.out.printf("                Accounts: %d%n", passwordManager.getAccountCount());
        System.out.println("=============================================");
        System.out.println("1.  Add Account");
        System.out.println("2.  View All Accounts");
        System.out.println("3.  Search Accounts");
        System.out.println("4.  View Account Details");
        System.out.println("5.  Edit Account");
        System.out.println("6.  Delete Account");
        System.out.println("7.  Password Generator");
        System.out.println("8.  Password Strength Checker");
        System.out.println("9.  Category Statistics");
        System.out.println("10. Lock Vault");
        System.out.println("11. Exit");
        System.out.println("=============================================");

        int choice = input.readInt("Enter choice: ", 1, 11);
        switch (choice) {
            case 1:
                handleAddAccount();
                break;
            case 2:
                handleViewAllAccounts();
                break;
            case 3:
                handleSearchAccounts();
                break;
            case 4:
                handleViewAccountDetails();
                break;
            case 5:
                handleEditAccount();
                break;
            case 6:
                handleDeleteAccount();
                break;
            case 7:
                handlePasswordGenerator();
                break;
            case 8:
                handleStrengthChecker();
                break;
            case 9:
                handleCategoryStatistics();
                break;
            case 10:
                handleLockVault();
                break;
            case 11:
                handleLockVault();
                return false;
        }
        return true;
    }

    /**
     * 1. Add Account
     */
    private void handleAddAccount() {
        System.out.println("\n=============================================");
        System.out.println("                 ADD ACCOUNT");
        System.out.println("=============================================");

        String website = input.readNonEmptyString("Website/App Name: ");
        String username = input.readNonEmptyString("Username/Email: ");

        System.out.println("\nPassword option:");
        System.out.println("1. Enter password manually");
        System.out.println("2. Generate strong password");
        int passChoice = input.readInt("Enter choice (1-2): ", 1, 2);

        String password;
        if (passChoice == 2) {
            password = passwordGenerator.generateDefault();
            System.out.println("Generated Password: " + password);
        } else {
            char[] passChars = input.readPassword("Password: ");
            password = new String(passChars);
            Arrays.fill(passChars, '\0');
        }

        String category = selectCategory();
        String notes = input.readString("Notes (optional): ");

        boolean confirm = input.readYesNo("\nSave account? (Y/N): ");
        if (confirm) {
            passwordManager.addEntry(website, username, password, category, notes);
            saveVaultChanges();
            System.out.println("Account added successfully.");
        } else {
            System.out.println("Action cancelled.");
        }
        input.pressEnterToContinue();
    }

    /**
     * Helper to select or customize category.
     */
    private String selectCategory() {
        System.out.println("\nSelect Category:");
        List<String> categories = PasswordManager.DEFAULT_CATEGORIES;
        for (int i = 0; i < categories.size(); i++) {
            System.out.printf("%d. %s%n", (i + 1), categories.get(i));
        }
        int catChoice = input.readInt("Enter category choice (1-" + categories.size() + "): ", 1, categories.size());
        String selected = categories.get(catChoice - 1);
        if ("Other".equalsIgnoreCase(selected)) {
            String custom = input.readString("Specify custom category (or press Enter for 'Other'): ");
            if (!custom.isEmpty()) {
                return custom;
            }
        }
        return selected;
    }

    /**
     * 2. View All Accounts
     */
    private void handleViewAllAccounts() {
        System.out.println("\n=============================================");
        System.out.println("                SAVED ACCOUNTS");
        System.out.println("=============================================");

        List<PasswordEntry> entries = passwordManager.getAllEntries();
        if (entries.isEmpty()) {
            System.out.println("No accounts stored in vault.");
        } else {
            printAccountsTable(entries);
        }
        input.pressEnterToContinue();
    }

    private void printAccountsTable(List<PasswordEntry> entries) {
        System.out.printf("%-6s | %-20s | %-28s | %-16s%n", "ID", "WEBSITE", "USERNAME", "CATEGORY");
        System.out.println("-------+----------------------+------------------------------+-----------------");
        for (PasswordEntry entry : entries) {
            String site = entry.getWebsite().length() > 20 ? entry.getWebsite().substring(0, 17) + "..." : entry.getWebsite();
            String user = entry.getUsername().length() > 28 ? entry.getUsername().substring(0, 25) + "..." : entry.getUsername();
            String cat = entry.getCategory().length() > 16 ? entry.getCategory().substring(0, 13) + "..." : entry.getCategory();
            System.out.printf("%-6d | %-20s | %-28s | %-16s%n", entry.getId(), site, user, cat);
        }
    }

    /**
     * 3. Search Accounts
     */
    private void handleSearchAccounts() {
        System.out.println("\n=============================================");
        System.out.println("               SEARCH ACCOUNTS");
        System.out.println("=============================================");
        System.out.println("1. Search by Website");
        System.out.println("2. Search by Username");
        System.out.println("3. Search by Category");
        System.out.println("4. Search by Keyword (all fields)");
        System.out.println("5. Back");

        int choice = input.readInt("Enter choice (1-5): ", 1, 5);
        if (choice == 5) {
            return;
        }

        String fieldType = "keyword";
        switch (choice) {
            case 1: fieldType = "website"; break;
            case 2: fieldType = "username"; break;
            case 3: fieldType = "category"; break;
            case 4: fieldType = "keyword"; break;
        }

        String query = input.readNonEmptyString("Enter search query: ");
        List<PasswordEntry> results = passwordManager.searchByField(fieldType, query);

        System.out.println("\nSearch Results:");
        if (results.isEmpty()) {
            System.out.println("No matching accounts found.");
        } else {
            printAccountsTable(results);
        }
        input.pressEnterToContinue();
    }

    /**
     * 4. View Account Details
     */
    private void handleViewAccountDetails() {
        System.out.println("\n=============================================");
        System.out.println("               ACCOUNT DETAILS");
        System.out.println("=============================================");

        int id = input.readAccountId("Enter Account ID: ");
        PasswordEntry entry = passwordManager.findById(id);

        if (entry == null) {
            System.out.printf("Error: Account with ID %d was not found.%n", id);
            input.pressEnterToContinue();
            return;
        }

        boolean showPassword = false;
        boolean viewing = true;

        while (viewing) {
            System.out.println("\n---------------------------------------------");
            System.out.println("ID:       " + entry.getId());
            System.out.println("Website:  " + entry.getWebsite());
            System.out.println("Username: " + entry.getUsername());
            System.out.println("Password: " + (showPassword ? entry.getPassword() : "********"));
            System.out.println("Category: " + entry.getCategory());
            System.out.println("Notes:    " + (entry.getNotes().isEmpty() ? "(None)" : entry.getNotes()));
            System.out.println("Created:  " + entry.getCreatedAt());
            System.out.println("Updated:  " + entry.getUpdatedAt());
            System.out.println("---------------------------------------------");
            System.out.println("1. " + (showPassword ? "Hide Password" : "Show Password"));
            System.out.println("2. Copy Password to Clipboard");
            System.out.println("3. Back");

            int option = input.readInt("Enter choice (1-3): ", 1, 3);
            switch (option) {
                case 1:
                    showPassword = !showPassword;
                    break;
                case 2:
                    if (ClipboardHelper.copyToClipboard(entry.getPassword())) {
                        System.out.println("Password copied to clipboard. (Auto-clears after 30 seconds)");
                    } else {
                        System.out.println("Clipboard is unavailable in this environment.");
                    }
                    break;
                case 3:
                    viewing = false;
                    break;
            }
        }
    }

    /**
     * 5. Edit Account
     */
    private void handleEditAccount() {
        System.out.println("\n=============================================");
        System.out.println("                 EDIT ACCOUNT");
        System.out.println("=============================================");

        int id = input.readAccountId("Enter Account ID: ");
        PasswordEntry entry = passwordManager.findById(id);

        if (entry == null) {
            System.out.printf("Error: Account with ID %d was not found.%n", id);
            input.pressEnterToContinue();
            return;
        }

        String newWebsite = entry.getWebsite();
        String newUsername = entry.getUsername();
        String newPassword = entry.getPassword();
        String newCategory = entry.getCategory();
        String newNotes = entry.getNotes();
        boolean hasChanges = false;

        boolean editing = true;
        while (editing) {
            System.out.println("\n---------------------------------------------");
            System.out.printf("Editing Account: %s (ID: %d)%n", newWebsite, entry.getId());
            System.out.println("---------------------------------------------");
            System.out.println("1. Change Website     (Current: " + newWebsite + ")");
            System.out.println("2. Change Username    (Current: " + newUsername + ")");
            System.out.println("3. Change Password    (Current: ********)");
            System.out.println("4. Change Category    (Current: " + newCategory + ")");
            System.out.println("5. Change Notes       (Current: " + (newNotes.isEmpty() ? "(None)" : newNotes) + ")");
            System.out.println("6. Save Changes");
            System.out.println("7. Cancel");

            int choice = input.readInt("Enter choice (1-7): ", 1, 7);
            switch (choice) {
                case 1:
                    newWebsite = input.readNonEmptyString("Enter new website/app name: ");
                    hasChanges = true;
                    break;
                case 2:
                    newUsername = input.readNonEmptyString("Enter new username/email: ");
                    hasChanges = true;
                    break;
                case 3:
                    System.out.println("1. Enter new password manually");
                    System.out.println("2. Generate strong password");
                    int pChoice = input.readInt("Choice (1-2): ", 1, 2);
                    if (pChoice == 2) {
                        newPassword = passwordGenerator.generateDefault();
                        System.out.println("Generated new password: " + newPassword);
                    } else {
                        char[] passChars = input.readPassword("Enter new password: ");
                        newPassword = new String(passChars);
                        Arrays.fill(passChars, '\0');
                    }
                    hasChanges = true;
                    break;
                case 4:
                    newCategory = selectCategory();
                    hasChanges = true;
                    break;
                case 5:
                    newNotes = input.readString("Enter new notes: ");
                    hasChanges = true;
                    break;
                case 6:
                    if (hasChanges) {
                        entry.setWebsite(newWebsite);
                        entry.setUsername(newUsername);
                        entry.setPassword(newPassword);
                        entry.setCategory(newCategory);
                        entry.setNotes(newNotes);
                        entry.touch();
                        saveVaultChanges();
                        System.out.println("Account changes saved successfully.");
                    } else {
                        System.out.println("No changes were made.");
                    }
                    editing = false;
                    break;
                case 7:
                    System.out.println("Editing cancelled.");
                    editing = false;
                    break;
            }
        }
        input.pressEnterToContinue();
    }

    /**
     * 6. Delete Account
     */
    private void handleDeleteAccount() {
        System.out.println("\n=============================================");
        System.out.println("                DELETE ACCOUNT");
        System.out.println("=============================================");

        int id = input.readAccountId("Enter Account ID: ");
        PasswordEntry entry = passwordManager.findById(id);

        if (entry == null) {
            System.out.printf("Error: Account with ID %d was not found.%n", id);
            input.pressEnterToContinue();
            return;
        }

        System.out.println("\nAccount to delete:");
        System.out.println("ID:       " + entry.getId());
        System.out.println("Website:  " + entry.getWebsite());
        System.out.println("Username: " + entry.getUsername());
        System.out.println("Category: " + entry.getCategory());
        System.out.println("Notes:    " + (entry.getNotes().isEmpty() ? "(None)" : entry.getNotes()));

        boolean confirm = input.readYesNo("\nAre you sure you want to delete this account? (Y/N): ");
        if (confirm) {
            passwordManager.deleteEntry(id);
            saveVaultChanges();
            System.out.println("Account deleted successfully.");
        } else {
            System.out.println("Deletion cancelled.");
        }
        input.pressEnterToContinue();
    }

    /**
     * 7. Password Generator
     */
    private void handlePasswordGenerator() {
        boolean active = true;
        while (active) {
            System.out.println("\n=============================================");
            System.out.println("             PASSWORD GENERATOR");
            System.out.println("=============================================");

            int length = input.readInt(String.format("Password length (%d-%d) [default 16]: ",
                    PasswordGenerator.MIN_LENGTH, PasswordGenerator.MAX_LENGTH),
                    PasswordGenerator.MIN_LENGTH, PasswordGenerator.MAX_LENGTH);

            boolean useUpper = input.readYesNo("Include uppercase letters? (Y/N): ");
            boolean useLower = input.readYesNo("Include lowercase letters? (Y/N): ");
            boolean useDigits = input.readYesNo("Include numbers? (Y/N): ");
            boolean useSymbols = input.readYesNo("Include symbols? (Y/N): ");

            if (!useUpper && !useLower && !useDigits && !useSymbols) {
                System.out.println("Error: You must select at least one character type.\n");
                continue;
            }

            boolean subLoop = true;
            while (subLoop) {
                String generated = passwordGenerator.generatePassword(length, useUpper, useLower, useDigits, useSymbols);
                System.out.println("\nGenerated Password:");
                System.out.println(generated);

                PasswordStrengthChecker.EvaluationResult strength = strengthChecker.evaluate(generated);
                System.out.println("Strength: " + strength.level.getLabel());

                System.out.println("\n1. Generate Again with same settings");
                System.out.println("2. Copy Password to Clipboard");
                System.out.println("3. Change Settings");
                System.out.println("4. Back to Main Menu");

                int choice = input.readInt("Enter choice (1-4): ", 1, 4);
                switch (choice) {
                    case 1:
                        // Generates new password in next iteration
                        break;
                    case 2:
                        if (ClipboardHelper.copyToClipboard(generated)) {
                            System.out.println("Password copied to clipboard. (Auto-clears after 30 seconds)");
                        } else {
                            System.out.println("Clipboard is unavailable.");
                        }
                        break;
                    case 3:
                        subLoop = false;
                        break;
                    case 4:
                        subLoop = false;
                        active = false;
                        break;
                }
            }
        }
    }

    /**
     * 8. Password Strength Checker
     */
    private void handleStrengthChecker() {
        System.out.println("\n=============================================");
        System.out.println("          PASSWORD STRENGTH CHECKER");
        System.out.println("=============================================");

        char[] passChars = input.readPassword("Enter password to test: ");
        String testPassword = new String(passChars);
        Arrays.fill(passChars, '\0');

        PasswordStrengthChecker.EvaluationResult res = strengthChecker.evaluate(testPassword);

        System.out.println("\nStrength Breakdown:");
        System.out.println("Length (>= 8 chars):   " + (res.hasMinLength ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("Length (>= 12 chars):  " + (res.hasGoodLength ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("Uppercase letters:     " + (res.hasUppercase ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("Lowercase letters:     " + (res.hasLowercase ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("Numbers (0-9):         " + (res.hasDigits ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("Special characters:    " + (res.hasSymbols ? "[✓] Passed" : "[✗] Failed"));
        System.out.println("---------------------------------------------");
        System.out.println("Overall Strength:      " + res.level.getLabel());
        System.out.println("=============================================");

        input.pressEnterToContinue();
    }

    /**
     * 9. Category Statistics
     */
    private void handleCategoryStatistics() {
        System.out.println("\n=============================================");
        System.out.println("             CATEGORY STATISTICS");
        System.out.println("=============================================");

        Map<String, Integer> counts = passwordManager.getCategoryCounts();
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            System.out.printf("%-18s %d%n", entry.getKey(), entry.getValue());
        }
        System.out.println("---------------------------------------------");
        System.out.printf("Total Accounts:    %d%n", passwordManager.getAccountCount());
        System.out.println("=============================================");

        input.pressEnterToContinue();
    }

    /**
     * 10. Lock Vault
     */
    private void handleLockVault() {
        if (authManager.isAuthenticated()) {
            saveVaultChanges();
            authManager.lock();
            passwordManager.clear();
            System.out.println("\nVault locked successfully.");
        }
    }

    /**
     * Saves active in-memory accounts into encrypted disk storage.
     */
    private void saveVaultChanges() {
        if (!authManager.isAuthenticated()) {
            return;
        }
        char[] sessionKey = authManager.getActiveSessionKey();
        try {
            vaultStorage.saveVault(passwordManager.getAllEntries(), sessionKey);
        } catch (Exception e) {
            System.out.println("Error saving encrypted vault: " + e.getMessage());
        } finally {
            Arrays.fill(sessionKey, '\0');
        }
    }
}
