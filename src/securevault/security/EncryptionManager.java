package securevault.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Handles all cryptographic operations for the password manager:
 * - PBKDF2WithHmacSHA256 for key derivation from master password
 * - AES-GCM (AES/GCM/NoPadding) for authenticated encryption and tamper detection
 * - SecureRandom for cryptographically secure salts and IV generation
 */
public class EncryptionManager {
    public static final int SALT_LENGTH = 32;       // 256-bit salt
    public static final int IV_LENGTH = 12;         // 96-bit standard GCM IV
    public static final int GCM_TAG_LENGTH = 128;   // 128-bit authentication tag
    public static final int PBKDF2_ITERATIONS = 65536;
    public static final int KEY_LENGTH = 256;       // 256-bit AES key

    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";

    private final SecureRandom secureRandom;

    public EncryptionManager() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a cryptographically secure random salt.
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a cryptographically secure random initialization vector (IV) for AES-GCM.
     */
    public byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Derives a 256-bit AES SecretKey from the master password and salt using PBKDF2WithHmacSHA256.
     *
     * @param masterPassword The master password characters
     * @param salt The cryptographic salt
     * @return AES SecretKey
     * @throws GeneralSecurityException if key derivation fails
     */
    public SecretKey deriveKey(char[] masterPassword, byte[] salt) throws GeneralSecurityException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            KeySpec spec = new PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, KEY_LENGTH);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            
            // Clean up temporary key bytes from memory
            Arrays.fill(keyBytes, (byte) 0);
            return secretKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new GeneralSecurityException("Failed to derive encryption key from master password.", e);
        }
    }

    /**
     * Encrypts plaintext bytes using AES/GCM/NoPadding.
     *
     * @param plainBytes Data to encrypt
     * @param key Derived SecretKey
     * @param iv Initialization vector
     * @return Ciphertext with authentication tag
     * @throws GeneralSecurityException if encryption fails
     */
    public byte[] encrypt(byte[] plainBytes, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(plainBytes);
    }

    /**
     * Decrypts ciphertext bytes using AES/GCM/NoPadding.
     * Automatically verifies authentication tag to detect wrong password or tampering.
     *
     * @param cipherBytes Encrypted data
     * @param key Derived SecretKey
     * @param iv Initialization vector
     * @return Decrypted plaintext bytes
     * @throws GeneralSecurityException if decryption or authentication fails
     */
    public byte[] decrypt(byte[] cipherBytes, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(cipherBytes);
    }
}
