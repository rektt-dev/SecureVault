# Project Statement: SecureVault

## 1. Problem Statement

With the rapid expansion of online services, education platforms, developer portals, and consumer applications, modern users must manage dozens of unique digital accounts. Consequently, individuals frequently resort to dangerous security habits, such as:
- Reusing simple, predictable passwords across multiple services.
- Storing login credentials in plain-text files, notes, or spreadsheets on local drives.
- Relying on proprietary cloud password managers that introduce third-party telemetry, subscription fees, internet dependencies, and single-point-of-failure breach risks.

There is a critical need for a lightweight, self-contained, offline credential manager that provides enterprise-grade authenticated encryption locally on the user's system while eliminating cloud vulnerabilities and plain-text exposure.

---

## 2. Scope of the Project

The scope of **SecureVault** is focused on delivering a standalone, terminal-driven password management application built with standard Java libraries:

### In Scope:
- **Offline Local Storage**: Secure, persistent storage of account credentials in an encrypted binary file format (`data/vault.dat`).
- **Cryptographic Security**: Implementation of PBKDF2 key derivation (HMAC-SHA256, 65,536 iterations, 256-bit salt) and authenticated symmetric encryption via AES-256-GCM with 96-bit random IVs and 128-bit authentication tags.
- **Master Authentication**: Single master password authentication protecting all underlying records without saving the master key to disk.
- **Account Operations (CRUD)**: Complete lifecycle management (creating, viewing, searching, modifying, deleting) for stored credentials.
- **Organization & Analytics**: Flexible categorical organization (*Social Media, Education, Development, Shopping, Entertainment, Finance, Work, Other*) and dynamic statistical distribution.
- **Security Utilities**: Built-in cryptographically secure password generation (`SecureRandom`) and multi-tier password strength checking.
- **Memory & Clipboard Safety**: Automatic memory clearing on vault lock and background auto-clearing of copied passwords after 30 seconds.

### Out of Scope:
- Cloud-based synchronization, external server communication, and third-party API integration.
- Graphical User Interfaces (GUIs) such as Swing, JavaFX, or web frontends.
- External database management systems (e.g., MySQL, MongoDB, SQLite).

---

## 3. Target Users

1. **Students & Developers**: Users looking for a lightweight, fast, terminal-accessible tool to manage credentials across coding platforms, servers, and academic portals.
2. **Security & Privacy-Conscious Individuals**: Users seeking complete control over their sensitive credentials without relying on cloud services, subscriptions, or proprietary software.
3. **Air-Gapped & Offline Environments**: Users and workstations operating in restricted or offline environments where internet access is unavailable or prohibited.
4. **Academic Evaluators & Java Learners**: Students and instructors reviewing robust implementations of object-oriented design (OOP), data structures, file I/O, exception handling, and Java Cryptography Architecture (JCA).

---

## 4. High-Level Features

| Feature | Description |
|---|---|
| **Master Key Derivation** | Derives a 256-bit AES key from the user's master password using PBKDF2-HMAC-SHA256 with a unique 32-byte salt. |
| **Authenticated Encryption** | Protects stored credentials using AES-GCM (256-bit), preventing unauthorized decryption and detecting file tampering. |
| **Credential Management** | Allows users to add, view, search, edit, and delete account credentials with auto-incrementing IDs and timestamps. |
| **Multi-Field Search** | Performs fast, case-insensitive searches across websites, usernames, categories, and keyword fields. |
| **Password Generator** | Generates strong, entropy-rich passwords with customizable lengths and character categories via `SecureRandom`. |
| **Strength Checker** | Evaluates password resilience across 5 criteria and classifies strength into 5 defined tiers (`VERY WEAK` to `VERY STRONG`). |
| **Category Statistics** | Aggregates and calculates account distribution counts dynamically across all categories. |
| **Timed Clipboard Clearing** | Copies passwords to the system clipboard and launches a background daemon thread to wipe the clipboard after 30 seconds. |
| **Session Locking** | Clears active in-memory session keys and data structures, requiring master password re-authentication. |
