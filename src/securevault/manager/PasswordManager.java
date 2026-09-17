package securevault.manager;

import securevault.model.PasswordEntry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages in-memory collection of password entries, handling CRUD operations,
 * search filters, and category statistics.
 */
public class PasswordManager {
    public static final List<String> DEFAULT_CATEGORIES = Collections.unmodifiableList(Arrays.asList(
            "Social Media",
            "Education",
            "Development",
            "Shopping",
            "Entertainment",
            "Finance",
            "Work",
            "Other"
    ));

    private final List<PasswordEntry> entries;
    private int nextId;

    public PasswordManager() {
        this.entries = new ArrayList<>();
        this.nextId = 1001;
    }

    /**
     * Initializes manager with loaded entries from storage.
     */
    public void setEntries(List<PasswordEntry> loadedEntries) {
        this.entries.clear();
        int maxId = 1000;
        if (loadedEntries != null) {
            for (PasswordEntry entry : loadedEntries) {
                this.entries.add(entry);
                if (entry.getId() > maxId) {
                    maxId = entry.getId();
                }
            }
        }
        this.nextId = maxId + 1;
    }

    /**
     * Adds a new password entry and assigns a unique ID.
     */
    public PasswordEntry addEntry(String website, String username, String password, String category, String notes) {
        PasswordEntry entry = new PasswordEntry(nextId++, website, username, password, category, notes);
        entries.add(entry);
        return entry;
    }

    /**
     * Adds an existing entry object.
     */
    public void addEntry(PasswordEntry entry) {
        if (entry.getId() <= 0) {
            entry.setId(nextId++);
        } else if (entry.getId() >= nextId) {
            nextId = entry.getId() + 1;
        }
        entries.add(entry);
    }

    /**
     * Retrieves an unmodifiable view of all stored password entries.
     */
    public List<PasswordEntry> getAllEntries() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    /**
     * Finds an entry by its unique ID.
     */
    public PasswordEntry findById(int id) {
        for (PasswordEntry entry : entries) {
            if (entry.getId() == id) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Searches entries across website, username, category, or notes.
     */
    public List<PasswordEntry> search(String query) {
        List<PasswordEntry> results = new ArrayList<>();
        if (query == null || query.trim().isEmpty()) {
            return results;
        }
        for (PasswordEntry entry : entries) {
            if (entry.matches(query)) {
                results.add(entry);
            }
        }
        return results;
    }

    /**
     * Searches entries by a specific field: Website, Username, Category, or Keyword.
     */
    public List<PasswordEntry> searchByField(String fieldType, String query) {
        if (query == null || query.trim().isEmpty()) {
            return Collections.emptyList();
        }
        String lowerQuery = query.toLowerCase().trim();
        List<PasswordEntry> results = new ArrayList<>();

        for (PasswordEntry entry : entries) {
            boolean match = false;
            switch (fieldType.toLowerCase()) {
                case "website":
                    match = entry.getWebsite() != null && entry.getWebsite().toLowerCase().contains(lowerQuery);
                    break;
                case "username":
                    match = entry.getUsername() != null && entry.getUsername().toLowerCase().contains(lowerQuery);
                    break;
                case "category":
                    match = entry.getCategory() != null && entry.getCategory().toLowerCase().contains(lowerQuery);
                    break;
                case "keyword":
                default:
                    match = entry.matches(lowerQuery);
                    break;
            }
            if (match) {
                results.add(entry);
            }
        }
        return results;
    }

    /**
     * Deletes an entry by its ID.
     */
    public boolean deleteEntry(int id) {
        return entries.removeIf(entry -> entry.getId() == id);
    }

    /**
     * Returns all entries belonging to a given category.
     */
    public List<PasswordEntry> getByCategory(String category) {
        List<PasswordEntry> results = new ArrayList<>();
        if (category == null) return results;
        for (PasswordEntry entry : entries) {
            if (category.equalsIgnoreCase(entry.getCategory())) {
                results.add(entry);
            }
        }
        return results;
    }

    /**
     * Computes statistics of account counts per category.
     */
    public Map<String, Integer> getCategoryCounts() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String cat : DEFAULT_CATEGORIES) {
            counts.put(cat, 0);
        }

        for (PasswordEntry entry : entries) {
            String cat = entry.getCategory();
            boolean found = false;
            for (String defaultCat : DEFAULT_CATEGORIES) {
                if (defaultCat.equalsIgnoreCase(cat)) {
                    counts.put(defaultCat, counts.get(defaultCat) + 1);
                    found = true;
                    break;
                }
            }
            if (!found) {
                counts.put("Other", counts.get("Other") + 1);
            }
        }

        return counts;
    }

    /**
     * Returns total count of accounts.
     */
    public int getAccountCount() {
        return entries.size();
    }

    /**
     * Clears in-memory accounts and resets IDs upon locking the vault.
     */
    public void clear() {
        for (PasswordEntry entry : entries) {
            entry.setPassword(""); // Wipe in-memory strings
        }
        entries.clear();
        nextId = 1001;
    }
}
