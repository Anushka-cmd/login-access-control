package com.lacms;

import com.lacms.security.PasswordUtil;
import org.junit.Test;

import static org.junit.Assert.*;

public class PasswordUtilTest {

    @Test
    public void hashesAreSaltedDifferentlyEvenForSamePassword() {
        String h1 = PasswordUtil.hash("Str0ng!Passw0rd");
        String h2 = PasswordUtil.hash("Str0ng!Passw0rd");
        assertNotEquals("two hashes of the same password must differ (random salt)", h1, h2);
    }

    @Test
    public void verifyAcceptsCorrectPassword() {
        String hash = PasswordUtil.hash("Correct#123");
        assertTrue(PasswordUtil.verify("Correct#123", hash));
    }

    @Test
    public void verifyRejectsWrongPassword() {
        String hash = PasswordUtil.hash("Correct#123");
        assertFalse(PasswordUtil.verify("Wrong#123", hash));
    }

    @Test
    public void verifyRejectsGarbageStoredHash() {
        assertFalse(PasswordUtil.verify("whatever", "not-a-real-hash"));
    }

    @Test
    public void hashNeverContainsThePlaintext() {
        String hash = PasswordUtil.hash("SuperSecret1!");
        assertFalse(hash.contains("SuperSecret1!"));
    }

    @Test
    public void storedFormatHasFourDollarSeparatedParts() {
        String hash = PasswordUtil.hash("AnotherOne1!");
        assertEquals(4, hash.split("\\$").length);
        assertTrue(hash.startsWith("pbkdf2_sha256$"));
    }
}
