package com.lacms;

import com.lacms.exception.ValidationException;
import com.lacms.security.InputValidator;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class InputValidatorTest {

    @Test(expected = ValidationException.class)
    public void rejectsTooShortUsername() {
        InputValidator.validateUsername("ab");
    }

    @Test(expected = ValidationException.class)
    public void rejectsUsernameWithSpaces() {
        InputValidator.validateUsername("john doe");
    }

    @Test
    public void acceptsNormalUsername() {
        InputValidator.validateUsername("john_doe_92");   // should not throw
    }

    @Test(expected = ValidationException.class)
    public void rejectsMalformedEmail() {
        InputValidator.validateEmail("not-an-email");
    }

    @Test
    public void acceptsNormalEmail() {
        InputValidator.validateEmail("john.doe@example.com");   // should not throw
    }

    @Test
    public void weakPasswordListsAllMissingRequirements() {
        List<String> problems = InputValidator.passwordProblems("weak", "john");
        assertFalse(problems.isEmpty());
    }

    @Test
    public void strongPasswordHasNoProblems() {
        List<String> problems = InputValidator.passwordProblems("Str0ng!Pass", "john");
        assertTrue(problems.isEmpty());
    }

    @Test
    public void passwordContainingUsernameIsRejected() {
        List<String> problems = InputValidator.passwordProblems("John123!456", "john");
        assertTrue(problems.stream().anyMatch(p -> p.contains("username")));
    }

    @Test
    public void sanitizeForLogStripsNewlinesToPreventLogForging() {
        String result = InputValidator.sanitizeForLog("admin\nFAKE LOG LINE INJECTED", 100);
        assertFalse(result.contains("\n"));
    }

    @Test
    public void sanitizeForLogTruncatesLongInput() {
        String longInput = "a".repeat(500);
        assertEquals(50, InputValidator.sanitizeForLog(longInput, 50).length());
    }
}
