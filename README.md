# SecureVault — Encrypted Password Manager

> A secure, offline, terminal-based password manager built with Java standard libraries, featuring authenticated AES-256-GCM encryption, PBKDF2 key derivation, and cryptographically secure password generation.

---

## 📌 Project Overview

**SecureVault** is an offline, terminal-based credential manager developed as a college Java project. The application demonstrates core object-oriented programming (OOP) principles, robust file handling, exception handling, data structures from the Java Collections Framework, and standard Java Cryptography APIs.

It allows users to store, organize, search, and manage login credentials for websites and applications locally in an encrypted database file without relying on external cloud services, third-party frameworks, or web APIs.

---

## ✨ Features

- **🔐 Authenticated Encryption (AES-256-GCM)**: All credentials are encrypted on disk using AES-256-GCM with a 128-bit authentication tag to protect data confidentiality and immediately detect tampering.
- **🔑 PBKDF2 Key Derivation**: Master passwords are never stored in plain text. Encryption keys are derived using `PBKDF2WithHmacSHA256` (65,536 iterations) and a unique 256-bit cryptographically random salt.
- **🗂️ Account Management (CRUD)**:
  - **Add Account**: Store website, username, password, category, and optional notes with unique auto-generated IDs.
  - **View Accounts**: Formatted tabular view with passwords hidden for shoulder-surfing protection.
  - **Search Accounts**: Case-insensitive search across websites, usernames, categories, or keywords.
  - **View Account Details**: Interactive details view with toggleable `Show/Hide Password` and `Copy to Clipboard`.
  - **Edit Account**: Modify individual account fields with automatic `updatedAt` timestamp tracking.
  - **Delete Account**: Safe deletion with explicit user confirmation.
- **🎲 Secure Password Generator**: Generate cryptographically secure passwords using `SecureRandom` with customizable lengths (6–128) and character sets (uppercase, lowercase, digits, symbols).
- **🛡️ Password Strength Checker**: Real-time evaluation of password entropy across 5 criteria (length, character classes) categorized into 5 strength tiers (`VERY WEAK` to `VERY STRONG`).
- **📊 Category Statistics**: Dynamic distribution and count of credentials across categories (*Social Media, Education, Development, Shopping, Entertainment, Finance, Work, Other*).
- **📋 Timed Clipboard Auto-Clear**: Automatically clears copied passwords from the system clipboard after 30 seconds.
- **🔒 Session Locking & Memory Sanitization**: Instantly flushes pending changes, clears sensitive in-memory buffers (`char[]`), and locks the vault back to the authentication screen.

---

## 🛠️ Technologies & Tools Used

| Component | Technology / API |
|---|---|
| **Language** | Java (JDK 8 / 11 / 17 / 21 / 24 compatible) |
| **User Interface** | Terminal / CLI (Standard I/O Streams) |
| **Cryptography** | `javax.crypto` (AES/GCM/NoPadding, PBKDF2WithHmacSHA256, SecretKeySpec), `java.security.SecureRandom` |
| **File I/O & Storage** | `java.io` (`File`, `FileInputStream`, `FileOutputStream`, `DataInputStream`, `DataOutputStream`, `ObjectInputStream`, `ObjectOutputStream`) |
| **Data Structures** | Java Collections Framework (`List`, `ArrayList`, `Map`, `LinkedHashMap`, `Collections`) |
| **Clipboard** | `java.awt.datatransfer` (`Clipboard`, `StringSelection`) |
| **Version Control** | Git & GitHub |

---

## 🚀 Steps to Install & Run

### Prerequisites
- **Java Development Kit (JDK 8 or higher)** installed on your machine.
- Verify your Java installation:
  ```bash
  javac -version
  java -version
  ```

### 1. Clone the Repository
```bash
git clone https://github.com/rektt-dev/SecureVault.git
cd SecureVault
```

### 2. Compile the Project
Compile all Java source files into the `bin` directory:
```bash
javac -d bin src/securevault/*.java src/securevault/*/*.java
```

### 3. Run the Application
```bash
java -cp bin securevault.Main
```

---

## 🧪 Instructions for Testing

Follow this step-by-step test plan to verify all core features:

### 1. First-Time Vault Creation
1. Launch the application when no `data/vault.dat` exists.
2. Select `1. Create New Vault`.
3. Enter a master password (minimum 6 characters) and confirm it.
4. Verify the password strength indicator is displayed.
5. Enter `Y` to create the encrypted vault.

### 2. Adding & Viewing Accounts
1. Select `1. Add Account`.
2. Enter website (e.g. `GitHub`), username (`student@gmail.com`), select category `3. Development`, and add optional notes.
3. Test both manual password input and option `2. Generate strong password`.
4. Select `2. View All Accounts` and verify passwords are hidden in the table view.

### 3. Viewing Details & Clipboard Copy
1. Select `4. View Account Details` and enter the account ID (`1001`).
2. Verify the password is masked (`********`).
3. Select `1. Show Password` to reveal it, then `1. Hide Password` to conceal it again.
4. Select `2. Copy Password to Clipboard` and verify it pastes into another app, then check that it clears after 30 seconds.

### 4. Searching & Editing
1. Select `3. Search Accounts` → `1. Search by Website` → query `git`. Verify case-insensitive match.
2. Select `5. Edit Account` → enter ID `1001` → modify notes or category → select `6. Save Changes`.

### 5. Utilities (Generator & Strength Checker)
1. Select `7. Password Generator` → test custom lengths and character sets.
2. Select `8. Password Strength Checker` → test simple (`abc`), medium (`Test1234`), and strong (`P@ssw0rd!#2026`) passwords.
3. Select `9. Category Statistics` to verify dynamic category counts.

### 6. Vault Locking & Persistence
1. Select `10. Lock Vault`. Verify session is locked and returns to login prompt.
2. Enter an incorrect master password → verify error message and remaining attempts counter.
3. Enter the correct master password → verify access is granted and accounts remain intact.
4. Exit the application (`11. Exit`), restart with `java -cp bin securevault.Main`, and verify data persists across restarts.

---

## 📸 Terminal Interface Preview

### Main Menu
```text
=============================================
                 SECUREVAULT
                Accounts: 3
=============================================
1.  Add Account
2.  View All Accounts
3.  Search Accounts
4.  View Account Details
5.  Edit Account
6.  Delete Account
7.  Password Generator
8.  Password Strength Checker
9.  Category Statistics
10. Lock Vault
11. Exit
=============================================
Enter choice:
```

### Saved Accounts View
```text
=============================================
                SAVED ACCOUNTS
=============================================
ID     | WEBSITE              | USERNAME                     | CATEGORY        
-------+----------------------+------------------------------+-----------------
1001   | GitHub               | student@gmail.com            | Development     
1002   | Instagram            | student_insta                | Social Media    
1003   | Amazon               | shopper@mail.com             | Shopping        
```

### Account Details View
```text
=============================================
               ACCOUNT DETAILS
=============================================
ID:       1001
Website:  GitHub
Username: student@gmail.com
Password: ********
Category: Development
Notes:    College repository login
Created:  17-09-2026 21:30
Updated:  17-09-2026 22:15
---------------------------------------------
1. Show Password
2. Copy Password to Clipboard
3. Back
```

---

## 🛡️ Security Architecture

```
Master Password
      ↓
[ Random 256-bit Salt ]
      ↓
PBKDF2WithHmacSHA256 (65,536 iterations)
      ↓
[ Derived 256-bit AES Key ]
      ↓
AES-GCM Authenticated Encryption (96-bit Random IV)
      ↓
[ data/vault.dat (Encrypted Binary Storage) ]
```

- **Zero Plaintext Storage**: Account passwords and master passwords are never stored in readable plain text.
- **Tamper Detection**: Corrupted or modified bytes in `data/vault.dat` trigger AES-GCM authentication failures, preventing unauthorized tampering.
- **Git Safety**: `data/vault.dat` is ignored in `.gitignore` to prevent committing encrypted or sensitive credential files.
