package securevault.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single credential entry in the password vault.
 * Fully encapsulated model holding account details, categorization, and timestamps.
 */
public class PasswordEntry implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");

    private int id;
    private String website;
    private String username;
    private String password;
    private String category;
    private String notes;
    private String createdAt;
    private String updatedAt;

    public PasswordEntry(int id, String website, String username, String password, String category, String notes) {
        this.id = id;
        this.website = website != null ? website.trim() : "";
        this.username = username != null ? username.trim() : "";
        this.password = password != null ? password : "";
        this.category = category != null ? category.trim() : "Other";
        this.notes = notes != null ? notes.trim() : "";
        
        String now = LocalDateTime.now().format(FORMATTER);
        this.createdAt = now;
        this.updatedAt = now;
    }

    public PasswordEntry(int id, String website, String username, String password, String category, String notes, String createdAt, String updatedAt) {
        this.id = id;
        this.website = website != null ? website.trim() : "";
        this.username = username != null ? username.trim() : "";
        this.password = password != null ? password : "";
        this.category = category != null ? category.trim() : "Other";
        this.notes = notes != null ? notes.trim() : "";
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website != null ? website.trim() : "";
        touch();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username != null ? username.trim() : "";
        touch();
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password != null ? password : "";
        touch();
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category != null ? category.trim() : "Other";
        touch();
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes != null ? notes.trim() : "";
        touch();
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Updates the last modified timestamp to current date and time.
     */
    public void touch() {
        this.updatedAt = LocalDateTime.now().format(FORMATTER);
    }

    /**
     * Checks if this entry matches a search query against website, username, category, or notes.
     */
    public boolean matches(String query) {
        if (query == null || query.trim().isEmpty()) {
            return false;
        }
        String lowerQuery = query.toLowerCase();
        return (website != null && website.toLowerCase().contains(lowerQuery)) ||
               (username != null && username.toLowerCase().contains(lowerQuery)) ||
               (category != null && category.toLowerCase().contains(lowerQuery)) ||
               (notes != null && notes.toLowerCase().contains(lowerQuery));
    }

    @Override
    public String toString() {
        return String.format("ID: %d | Website: %s | Username: %s | Category: %s", id, website, username, category);
    }
}
