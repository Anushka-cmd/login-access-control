package com.lacms.service;

import com.lacms.model.User;

public class LoginResult {
    private final boolean success;
    private final boolean locked;
    private final User user;
    private final String message;

    private LoginResult(boolean success, boolean locked, User user, String message) {
        this.success = success;
        this.locked = locked;
        this.user = user;
        this.message = message;
    }

    public static LoginResult success(User user) { return new LoginResult(true, false, user, "Login successful."); }
    public static LoginResult failure(String message) { return new LoginResult(false, false, null, message); }
    public static LoginResult locked(String message) { return new LoginResult(false, true, null, message); }

    public boolean isSuccess() { return success; }
    public boolean isLocked() { return locked; }
    public User getUser() { return user; }
    public String getMessage() { return message; }
}
