package com.lacms.security;

import com.lacms.exception.ValidationException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Server-side validation for every piece of user-supplied data. */
public final class InputValidator {

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_]{3,30}$");
    private static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    public static final int MIN_PASSWORD_LENGTH = 8;
    public static final int MAX_PASSWORD_LENGTH = 128;

    private InputValidator() { }

    public static void validateUsername(String username) {
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new ValidationException(
                    "Username must be 3-30 characters: letters, digits or underscore only.");
        }
    }

    public static void validateEmail(String email) {
        if (email == null || email.length() > 120 || !EMAIL.matcher(email).matches()) {
            throw new ValidationException("Please enter a valid email address.");
        }
    }

    public static void validatePassword(String password, String username) {
        List<String> problems = passwordProblems(password, username);
        if (!problems.isEmpty()) {
            throw new ValidationException("Weak password: " + String.join("; ", problems) + ".");
        }
    }

    public static List<String> passwordProblems(String password, String username) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            problems.add("at least " + MIN_PASSWORD_LENGTH + " characters");
            return problems;
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            problems.add("at most " + MAX_PASSWORD_LENGTH + " characters");
        }
        if (!password.matches(".*[A-Z].*")) problems.add("one uppercase letter");
        if (!password.matches(".*[a-z].*")) problems.add("one lowercase letter");
        if (!password.matches(".*\\d.*")) problems.add("one digit");
        if (!password.matches(".*[^A-Za-z0-9].*")) problems.add("one special character");
        if (username != null && !username.isEmpty()
                && password.toLowerCase().contains(username.toLowerCase())) {
            problems.add("must not contain the username");
        }
        return problems;
    }

    /**
     * Makes attacker-controlled text safe to store in audit tables:
     * strips control characters (log-forging via newlines) and truncates.
     */
    public static String sanitizeForLog(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replaceAll("\\p{Cntrl}", "?");
        return cleaned.length() > maxLength ? cleaned.substring(0, maxLength) : cleaned;
    }
}
