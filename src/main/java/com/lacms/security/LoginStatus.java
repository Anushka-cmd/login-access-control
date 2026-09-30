package com.lacms.security;

/** Values written to login_history.status */
public final class LoginStatus {
    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED_BAD_PASSWORD = "FAILED_BAD_PASSWORD";
    public static final String FAILED_UNKNOWN_USER = "FAILED_UNKNOWN_USER";
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";     // this attempt caused the lock
    public static final String BLOCKED_LOCKED = "BLOCKED_LOCKED";     // attempt on an already-locked account

    private LoginStatus() { }
}
