package securevault.security;

import securevault.model.PasswordEntry;
import securevault.storage.VaultStorage;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

/**
 * Manages user authentication state, session lifecycle, and master password memory security.
 */
public class AuthenticationManager {
    private final VaultStorage vaultStorage;
    private char[] activeSessionKey;
    private boolean authenticated;

    public AuthenticationManager(VaultStorage vaultStorage) {
        this.vaultStorage = vaultStorage;
        this.activeSessionKey = null;
        this.authenticated = false;
    }

    /**
     * Checks if a user is currently authenticated.
     */
    public boolean isAuthenticated() {
        return authenticated && activeSessionKey != null;
    }

    /**
     * Authenticates the user by attempting to decrypt the vault using the supplied master password.
     *
     * @param masterPassword Master password provided by the user
     * @return Decrypted list of entries if authentication succeeds
     * @throws GeneralSecurityException if authentication fails (wrong password or corrupted vault)
     * @throws Exception on I/O or deserialization errors
     */
    public List<PasswordEntry> authenticate(char[] masterPassword) throws Exception {
        try {
            List<PasswordEntry> entries = vaultStorage.loadVault(masterPassword);
            setSessionKey(masterPassword);
            this.authenticated = true;
            return entries;
        } catch (GeneralSecurityException e) {
            lock();
            throw e;
        }
    }

    /**
     * Sets the active master password for current session after successful vault creation.
     */
    public void establishSession(char[] masterPassword) {
        setSessionKey(masterPassword);
        this.authenticated = true;
    }

    /**
     * Returns a copy of the active session master password for saving changes.
     */
    public char[] getActiveSessionKey() {
        if (!isAuthenticated()) {
            throw new IllegalStateException("User is not authenticated.");
        }
        return Arrays.copyOf(activeSessionKey, activeSessionKey.length);
    }

    private void setSessionKey(char[] masterPassword) {
        if (this.activeSessionKey != null) {
            Arrays.fill(this.activeSessionKey, '\0');
        }
        this.activeSessionKey = Arrays.copyOf(masterPassword, masterPassword.length);
    }

    /**
     * Locks the vault, zeroes out sensitive master password data in memory, and resets session state.
     */
    public void lock() {
        if (this.activeSessionKey != null) {
            Arrays.fill(this.activeSessionKey, '\0');
            this.activeSessionKey = null;
        }
        this.authenticated = false;
    }
}
