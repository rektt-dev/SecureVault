package securevault.util;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;

/**
 * Utility for securely copying sensitive passwords to the system clipboard
 * with automatic timed clearing after 30 seconds.
 */
public class ClipboardHelper {
    private static final int CLEAR_DELAY_MS = 30000; // 30 seconds

    /**
     * Copies the given text to clipboard and schedules auto-clearing.
     *
     * @param text The text to copy
     * @return true if copied successfully, false otherwise
     */
    public static boolean copyToClipboard(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection selection = new StringSelection(text);
            clipboard.setContents(selection, null);

            // Schedule background daemon thread to wipe clipboard after 30 seconds
            Thread cleanerThread = new Thread(() -> {
                try {
                    Thread.sleep(CLEAR_DELAY_MS);
                    Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
                    Transferable currentContents = cb.getContents(null);
                    if (currentContents != null && currentContents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
                        String current = (String) currentContents.getTransferData(DataFlavor.stringFlavor);
                        // Only clear if the content has not been replaced by something else
                        if (text.equals(current)) {
                            StringSelection emptySelection = new StringSelection("");
                            cb.setContents(emptySelection, null);
                        }
                    }
                } catch (Exception ignored) {
                    // Fail silently for background clearing
                }
            });
            cleanerThread.setDaemon(true);
            cleanerThread.setName("Clipboard-Cleaner");
            cleanerThread.start();

            return true;
        } catch (Throwable t) {
            // Headless or permission failure
            return false;
        }
    }
}
