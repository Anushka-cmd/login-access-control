package com.lacms.security;

/** Permission names; they must match the rows seeded in db/schema.sql. */
public final class Permissions {
    public static final String VIEW_OWN_PROFILE = "VIEW_OWN_PROFILE";
    public static final String CHANGE_OWN_PASSWORD = "CHANGE_OWN_PASSWORD";
    public static final String VIEW_OWN_LOGIN_HISTORY = "VIEW_OWN_LOGIN_HISTORY";
    public static final String VIEW_USERS = "VIEW_USERS";
    public static final String VIEW_REPORTS = "VIEW_REPORTS";
    public static final String CREATE_USER = "CREATE_USER";
    public static final String ASSIGN_ROLE = "ASSIGN_ROLE";
    public static final String UNLOCK_ACCOUNT = "UNLOCK_ACCOUNT";
    public static final String DELETE_USER = "DELETE_USER";
    public static final String VIEW_ALL_LOGIN_HISTORY = "VIEW_ALL_LOGIN_HISTORY";
    public static final String VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG";

    private Permissions() { }
}
