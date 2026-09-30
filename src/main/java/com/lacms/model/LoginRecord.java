package com.lacms.model;

import java.time.LocalDateTime;

public class LoginRecord {
    private final long historyId;
    private final Integer userId;
    private final String usernameAttempted;
    private final String status;
    private final String detail;
    private final LocalDateTime attemptedAt;

    public LoginRecord(long historyId, Integer userId, String usernameAttempted,
                       String status, String detail, LocalDateTime attemptedAt) {
        this.historyId = historyId;
        this.userId = userId;
        this.usernameAttempted = usernameAttempted;
        this.status = status;
        this.detail = detail;
        this.attemptedAt = attemptedAt;
    }

    public long getHistoryId() { return historyId; }
    public Integer getUserId() { return userId; }
    public String getUsernameAttempted() { return usernameAttempted; }
    public String getStatus() { return status; }
    public String getDetail() { return detail; }
    public LocalDateTime getAttemptedAt() { return attemptedAt; }
}
