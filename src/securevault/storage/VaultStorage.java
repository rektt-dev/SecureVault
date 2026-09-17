package securevault.storage;

import securevault.model.PasswordEntry;
import securevault.security.EncryptionManager;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles persistent storage of the encrypted password vault on disk.
 * Encapsulates serialization, encryption, file I/O, and integrity verification.
 */
public class VaultStorage {
    private static final int MAGIC_HEADER = 0x53564C54; // "SVLT" (SecureVault)
    private static final int FILE_VERSION = 1;

    private final String vaultFilePath;
    private final EncryptionManager encryptionManager;

    public VaultStorage(String vaultFilePath, EncryptionManager encryptionManager) {
        this.vaultFilePath = vaultFilePath;
        this.encryptionManager = encryptionManager;
    }

    /**
     * Checks whether a vault file already exists.
     */
    public boolean vaultExists() {
        File file = new File(vaultFilePath);
        return file.exists() && file.isFile() && file.length() > 0;
    }

    /**
     * Creates a new encrypted empty vault.
     */
    public void createNewVault(char[] masterPassword) throws IOException, GeneralSecurityException {
        saveVault(new ArrayList<>(), masterPassword);
    }

    /**
     * Serializes and encrypts password entries, writing to the vault file.
     *
     * @param entries List of password entries to store
     * @param masterPassword Master password used to derive the encryption key
     * @throws IOException on I/O failure
     * @throws GeneralSecurityException on encryption failure
     */
    public void saveVault(List<PasswordEntry> entries, char[] masterPassword) throws IOException, GeneralSecurityException {
        File vaultFile = new File(vaultFilePath);
        File parentDir = vaultFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        // 1. Serialize entries to in-memory byte array
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try (ObjectOutputStream objOut = new ObjectOutputStream(byteOut)) {
            objOut.writeObject(new ArrayList<>(entries));
            objOut.flush();
        }
        byte[] plaintextData = byteOut.toByteArray();

        // 2. Generate random salt and IV
        byte[] salt = encryptionManager.generateSalt();
        byte[] iv = encryptionManager.generateIV();

        // 3. Derive key and encrypt plaintext payload
        SecretKey secretKey = encryptionManager.deriveKey(masterPassword, salt);
        byte[] ciphertext = encryptionManager.encrypt(plaintextData, secretKey, iv);

        // 4. Write header + salt + IV + ciphertext to file
        try (FileOutputStream fos = new FileOutputStream(vaultFile);
             DataOutputStream dos = new DataOutputStream(fos)) {
            dos.writeInt(MAGIC_HEADER);
            dos.writeInt(FILE_VERSION);
            
            dos.writeInt(salt.length);
            dos.write(salt);
            
            dos.writeInt(iv.length);
            dos.write(iv);
            
            dos.writeInt(ciphertext.length);
            dos.write(ciphertext);
            
            dos.flush();
        }
    }

    /**
     * Reads, decrypts, and deserializes password entries from the vault file.
     *
     * @param masterPassword Master password provided for authentication
     * @return List of decrypted PasswordEntry objects
     * @throws IOException on file reading failure or invalid file format
     * @throws GeneralSecurityException on authentication/decryption failure (wrong password or tampered data)
     */
    @SuppressWarnings("unchecked")
    public List<PasswordEntry> loadVault(char[] masterPassword) throws IOException, GeneralSecurityException, ClassNotFoundException {
        File vaultFile = new File(vaultFilePath);
        if (!vaultFile.exists()) {
            throw new IOException("Vault file not found at: " + vaultFilePath);
        }

        byte[] salt;
        byte[] iv;
        byte[] ciphertext;

        try (FileInputStream fis = new FileInputStream(vaultFile);
             DataInputStream dis = new DataInputStream(fis)) {
            int magic = dis.readInt();
            if (magic != MAGIC_HEADER) {
                throw new IOException("Invalid file format. The file is not a valid SecureVault database.");
            }
            int version = dis.readInt();
            if (version != FILE_VERSION) {
                throw new IOException("Unsupported vault file version: " + version);
            }

            int saltLength = dis.readInt();
            if (saltLength <= 0 || saltLength > 256) {
                throw new IOException("Corrupted vault metadata: invalid salt length.");
            }
            salt = new byte[saltLength];
            dis.readFully(salt);

            int ivLength = dis.readInt();
            if (ivLength <= 0 || ivLength > 128) {
                throw new IOException("Corrupted vault metadata: invalid IV length.");
            }
            iv = new byte[ivLength];
            dis.readFully(iv);

            int cipherLength = dis.readInt();
            if (cipherLength <= 0 || cipherLength > 100 * 1024 * 1024) { // 100 MB max sanity check
                throw new IOException("Corrupted vault metadata: invalid ciphertext length.");
            }
            ciphertext = new byte[cipherLength];
            dis.readFully(ciphertext);
        }

        // Derive key and decrypt payload (AES-GCM checks auth tag)
        SecretKey secretKey = encryptionManager.deriveKey(masterPassword, salt);
        byte[] decryptedData = encryptionManager.decrypt(ciphertext, secretKey, iv);

        // Deserialize objects
        try (ByteArrayInputStream byteIn = new ByteArrayInputStream(decryptedData);
             ObjectInputStream objIn = new ObjectInputStream(byteIn)) {
            Object obj = objIn.readObject();
            if (obj instanceof List<?>) {
                return (List<PasswordEntry>) obj;
            } else {
                throw new IOException("Corrupted vault payload format.");
            }
        }
    }
}
