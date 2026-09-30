package com.lacms.dao;

import com.lacms.config.DBConnection;
import com.lacms.exception.DataAccessException;
import com.lacms.exception.DuplicateUserException;
import com.lacms.exception.ValidationException;
import com.lacms.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** All SQL touching the users table. Every statement is a PreparedStatement. */
public class UserDAO {

    private static final String SELECT_USER =
            "SELECT u.user_id, u.username, u.email, u.password_hash, u.role_id, r.role_name, "
          + "u.failed_attempts, u.is_locked, u.locked_at, u.created_at, u.last_login_at "
          + "FROM users u JOIN roles r ON u.role_id = r.role_id ";

    /** Result of recording a failed login. */
    public static class AttemptResult {
        public final int attempts;
        public final boolean lockedNow;

        AttemptResult(int attempts, boolean lockedNow) {
            this.attempts = attempts;
            this.lockedNow = lockedNow;
        }
    }

    // ------------------------------------------------------------ CREATE
    public int createUser(String username, String email, String passwordHash, String roleName) {
        String sql = "INSERT INTO users (username, email, password_hash, role_id) "
                   + "SELECT ?, ?, ?, role_id FROM roles WHERE role_name = ?";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username);
            ps.setString(2, email);
            ps.setString(3, passwordHash);
            ps.setString(4, roleName);
            if (ps.executeUpdate() == 0) {
                throw new ValidationException("Unknown role: " + roleName);
            }
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getInt(1) : -1;
            }
        } catch (SQLException e) {
            if (e.getSQLState() != null && e.getSQLState().startsWith("23")) {
                throw new DuplicateUserException("Username or email is already registered.");
            }
            throw new DataAccessException("Could not create user", e);
        }
    }

    // ------------------------------------------------------------ READ
    public Optional<User> findByUsername(String username) {
        return findOne(SELECT_USER + "WHERE u.username = ?", username);
    }

    public Optional<User> findById(int userId) {
        return findOne(SELECT_USER + "WHERE u.user_id = ?", userId);
    }

    public List<User> findAll() {
        List<User> users = new ArrayList<>();
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(SELECT_USER + "ORDER BY u.user_id");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                users.add(map(rs));
            }
            return users;
        } catch (SQLException e) {
            throw new DataAccessException("Could not list users", e);
        }
    }

    public int countByRole(String roleName) {
        String sql = "SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id = r.role_id WHERE r.role_name = ?";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, roleName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not count users", e);
        }
    }

    public Map<String, Integer> countUsersPerRole() {
        String sql = "SELECT r.role_name, COUNT(u.user_id) FROM roles r "
                   + "LEFT JOIN users u ON u.role_id = r.role_id GROUP BY r.role_name ORDER BY r.role_name";
        Map<String, Integer> result = new LinkedHashMap<>();
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                result.put(rs.getString(1), rs.getInt(2));
            }
            return result;
        } catch (SQLException e) {
            throw new DataAccessException("Could not count users per role", e);
        }
    }

    public int countLocked() {
        return scalarInt("SELECT COUNT(*) FROM users WHERE is_locked = TRUE");
    }

    // ------------------------------------------------------------ UPDATE
    /** Successful login: clear the failure counter and stamp last_login_at. */
    public void recordSuccessfulLogin(int userId) {
        executeUpdate("UPDATE users SET failed_attempts = 0, last_login_at = NOW() WHERE user_id = ?", userId);
    }

    /**
     * Failed login: increment the counter and lock the account when it
     * reaches maxAttempts. Runs in one transaction so two parallel bad
     * logins cannot both slip under the threshold.
     */
    public AttemptResult recordFailedAttempt(int userId, int maxAttempts) {
        try (Connection c = DBConnection.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement inc = c.prepareStatement(
                        "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE user_id = ?")) {
                    inc.setInt(1, userId);
                    inc.executeUpdate();
                }
                int attempts = 0;
                try (PreparedStatement sel = c.prepareStatement(
                        "SELECT failed_attempts FROM users WHERE user_id = ? FOR UPDATE")) {
                    sel.setInt(1, userId);
                    try (ResultSet rs = sel.executeQuery()) {
                        if (rs.next()) {
                            attempts = rs.getInt(1);
                        }
                    }
                }
                boolean lockedNow = false;
                if (attempts >= maxAttempts) {
                    try (PreparedStatement lock = c.prepareStatement(
                            "UPDATE users SET is_locked = TRUE, locked_at = NOW() "
                          + "WHERE user_id = ? AND is_locked = FALSE")) {
                        lock.setInt(1, userId);
                        lockedNow = lock.executeUpdate() > 0;
                    }
                }
                c.commit();
                return new AttemptResult(attempts, lockedNow);
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not record failed login", e);
        }
    }

    public boolean unlockAccount(int userId) {
        return executeUpdate("UPDATE users SET is_locked = FALSE, locked_at = NULL, failed_attempts = 0 "
                           + "WHERE user_id = ?", userId) > 0;
    }

    public boolean updateRole(int userId, String roleName) {
        return executeUpdate("UPDATE users SET role_id = (SELECT role_id FROM roles WHERE role_name = ?) "
                           + "WHERE user_id = ?", roleName, userId) > 0;
    }

    public boolean updatePassword(int userId, String newHash) {
        return executeUpdate("UPDATE users SET password_hash = ?, failed_attempts = 0 WHERE user_id = ?",
                             newHash, userId) > 0;
    }

    // ------------------------------------------------------------ DELETE
    public boolean deleteUser(int userId) {
        return executeUpdate("DELETE FROM users WHERE user_id = ?", userId) > 0;
    }

    // ------------------------------------------------------------ helpers
    private Optional<User> findOne(String sql, Object param) {
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not query user", e);
        }
    }

    private int executeUpdate(String sql, Object... params) {
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setObject(i + 1, params[i]);
            }
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException("Database update failed", e);
        }
    }

    private int scalarInt(String sql) {
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new DataAccessException("Database query failed", e);
        }
    }

    private static User map(ResultSet rs) throws SQLException {
        return new User(
                rs.getInt("user_id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getInt("role_id"),
                rs.getString("role_name"),
                rs.getInt("failed_attempts"),
                rs.getBoolean("is_locked"),
                toLdt(rs.getTimestamp("locked_at")),
                toLdt(rs.getTimestamp("created_at")),
                toLdt(rs.getTimestamp("last_login_at")));
    }

    static LocalDateTime toLdt(Timestamp ts) {
        return ts == null ? null : ts.toLocalDateTime();
    }
}
