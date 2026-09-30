package com.lacms.model;

import java.time.LocalDateTime;

public class User {
    private final int userId;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final int roleId;
    private final String roleName;
    private final int failedAttempts;
    private final boolean locked;
    private final LocalDateTime lockedAt;
    private final LocalDateTime createdAt;
    private final LocalDateTime lastLoginAt;

    public User(int userId, String username, String email, String passwordHash,
                int roleId, String roleName, int failedAttempts, boolean locked,
                LocalDateTime lockedAt, LocalDateTime createdAt, LocalDateTime lastLoginAt) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.roleId = roleId;
        this.roleName = roleName;
        this.failedAttempts = failedAttempts;
        this.locked = locked;
        this.lockedAt = lockedAt;
        this.createdAt = createdAt;
        this.lastLoginAt = lastLoginAt;
    }

    public int getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public int getRoleId() { return roleId; }
    public String getRoleName() { return roleName; }
    public int getFailedAttempts() { return failedAttempts; }
    public boolean isLocked() { return locked; }
    public LocalDateTime getLockedAt() { return lockedAt; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getLastLoginAt() { return lastLoginAt; }

    /** Deliberately excludes the password hash so it can never leak into logs. */
    @Override
    public String toString() {
        return "User{id=" + userId + ", username='" + username + "', role=" + roleName
                + ", locked=" + locked + "}";
    }
}
