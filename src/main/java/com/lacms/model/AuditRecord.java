package com.lacms.model;

import java.time.LocalDateTime;

public class AuditRecord {
    private final long auditId;
    private final String actorUsername;
    private final String action;
    private final String targetUsername;
    private final String detail;
    private final LocalDateTime createdAt;

    public AuditRecord(long auditId, String actorUsername, String action,
                       String targetUsername, String detail, LocalDateTime createdAt) {
        this.auditId = auditId;
        this.actorUsername = actorUsername;
        this.action = action;
        this.targetUsername = targetUsername;
        this.detail = detail;
        this.createdAt = createdAt;
    }

    public long getAuditId() { return auditId; }
    public String getActorUsername() { return actorUsername; }
    public String getAction() { return action; }
    public String getTargetUsername() { return targetUsername; }
    public String getDetail() { return detail; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
