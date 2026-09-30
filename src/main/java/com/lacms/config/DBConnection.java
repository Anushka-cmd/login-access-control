package com.lacms.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Central place for JDBC connections.
 * Credentials come from environment variables so no password is ever
 * hard-coded or committed to Git:
 *   LACMS_DB_URL       (default jdbc:mysql://localhost:3306/access_control_db)
 *   LACMS_DB_USER      (default root)
 *   LACMS_DB_PASSWORD  (default empty)
 */
public final class DBConnection {

    private static final String URL =
            env("LACMS_DB_URL", "jdbc:mysql://localhost:3306/access_control_db");
    private static final String USER = env("LACMS_DB_USER", "root");
    private static final String PASSWORD = env("LACMS_DB_PASSWORD", "");

    private DBConnection() { }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    public static String getUrl() {
        return URL;
    }

    /** Quick health check used at start-up to give a friendly error. */
    public static boolean isReachable() {
        try (Connection c = getConnection()) {
            return c.isValid(3);
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
            return false;
        }
    }

    private static String env(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? fallback : v;
    }
}
