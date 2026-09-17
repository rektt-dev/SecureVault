# SecureVault — Encrypted Password Manager

SecureVault is an offline, terminal-based credential manager written in pure Java. It provides a secure local vault for managing login credentials across categories, featuring PBKDF2 key derivation, authenticated AES-256-GCM encryption, password generation, and password strength evaluation.

## Features

- **Authenticated AES-GCM Encryption**: Encrypts all vault data locally on disk using AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation.
- **Account Management (CRUD)**: Add, view, search, edit, and delete credentials organized by categories.
- **Search & Filtering**: Case-insensitive search across websites, usernames, categories, and keywords.
- **Credential Privacy**: Hidden password display by default with interactive reveal and clipboard copying (with auto-clear).
- **Password Generator**: Cryptographically secure random password generation with customizable character sets and length.
- **Strength Evaluator**: Real-time password strength and entropy assessment.
- **Category Statistics**: Dynamic summary of stored accounts categorized across predefined groups.
- **Vault Locking**: Instant memory sanitization and session locking.

## Requirements

- **Java Development Kit (JDK)**: Java 8 or higher (tested on JDK 8, 17, 21, and 24).
- **Operating System**: Windows, macOS, or Linux.
- **Dependencies**: None (uses standard Java SE libraries only).

## How to Run

### 1. Clone the repository
```bash
git clone <repo-url>
cd SecureVault
```

### 2. Compile the source code
```bash
javac -d bin src/securevault/*.java src/securevault/*/*.java
```

### 3. Run the application
```bash
java -cp bin securevault.Main
```

## Basic Usage

1. **First Launch**: When no vault exists, select `1. Create New Vault`, set a master password, and confirm.
2. **Unlocking**: Enter your master password at startup. Three unsuccessful attempts will exit the application.
3. **Adding Accounts**: Select `1. Add Account` from the main menu, enter credentials, and choose a category.
4. **Viewing & Copying**: Select `2. View All Accounts` to see all stored items or `4. View Account Details` to toggle password visibility or copy to clipboard.
5. **Locking & Exiting**: Select `10. Lock Vault` to secure in-memory data and return to the login screen, or `11. Exit` to save and quit.

## Security Architecture

- **Key Derivation**: `PBKDF2WithHmacSHA256` with 65,536 iterations and a 256-bit cryptographically random salt per vault.
- **Cipher**: `AES/GCM/NoPadding` with unique 96-bit IVs per save operation and a 128-bit authentication tag for tamper detection.
- **Memory Safety**: In-memory password fields and sensitive character arrays are cleared upon vault lock and session teardown.
- **Storage**: Stored in binary format in `data/vault.dat` (excluded from version control).
