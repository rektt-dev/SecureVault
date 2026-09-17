package securevault.security;

/**
 * Evaluates password strength based on length and character entropy criteria:
 * - Length (< 6, >= 8, >= 12, >= 16)
 * - Uppercase letters (A-Z)
 * - Lowercase letters (a-z)
 * - Digits (0-9)
 * - Special characters
 */
public class PasswordStrengthChecker {

    public enum StrengthLevel {
        VERY_WEAK("VERY WEAK"),
        WEAK("WEAK"),
        MEDIUM("MEDIUM"),
        STRONG("STRONG"),
        VERY_STRONG("VERY STRONG");

        private final String label;

        StrengthLevel(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

    public static class EvaluationResult {
        public final boolean hasMinLength;    // >= 8
        public final boolean hasGoodLength;   // >= 12
        public final boolean hasUppercase;
        public final boolean hasLowercase;
        public final boolean hasDigits;
        public final boolean hasSymbols;
        public final int score;
        public final StrengthLevel level;

        public EvaluationResult(boolean hasMinLength, boolean hasGoodLength, boolean hasUppercase,
                                boolean hasLowercase, boolean hasDigits, boolean hasSymbols,
                                int score, StrengthLevel level) {
            this.hasMinLength = hasMinLength;
            this.hasGoodLength = hasGoodLength;
            this.hasUppercase = hasUppercase;
            this.hasLowercase = hasLowercase;
            this.hasDigits = hasDigits;
            this.hasSymbols = hasSymbols;
            this.score = score;
            this.level = level;
        }
    }

    /**
     * Evaluates the provided password and returns a detailed EvaluationResult.
     */
    public EvaluationResult evaluate(String password) {
        if (password == null || password.isEmpty()) {
            return new EvaluationResult(false, false, false, false, false, false, 0, StrengthLevel.VERY_WEAK);
        }

        int len = password.length();
        boolean hasMinLength = len >= 8;
        boolean hasGoodLength = len >= 12;
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigits = false;
        boolean hasSymbols = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowercase = true;
            } else if (Character.isDigit(c)) {
                hasDigits = true;
            } else {
                hasSymbols = true;
            }
        }

        // Calculate score
        int score = 0;
        if (len >= 8) score++;
        if (len >= 12) score++;
        if (len >= 16) score++;
        if (hasUppercase) score++;
        if (hasLowercase) score++;
        if (hasDigits) score++;
        if (hasSymbols) score++;

        StrengthLevel level;
        if (len < 6 || score <= 2) {
            level = StrengthLevel.VERY_WEAK;
        } else if (score == 3) {
            level = StrengthLevel.WEAK;
        } else if (score == 4 || score == 5) {
            level = StrengthLevel.MEDIUM;
        } else if (score == 6) {
            level = StrengthLevel.STRONG;
        } else {
            level = StrengthLevel.VERY_STRONG;
        }

        return new EvaluationResult(hasMinLength, hasGoodLength, hasUppercase, hasLowercase, hasDigits, hasSymbols, score, level);
    }
}
