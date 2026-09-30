package com.lacms.dao;

import com.lacms.config.DBConnection;
import com.lacms.exception.DataAccessException;
import com.lacms.model.LoginRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

/** Append-only trail of every login attempt. */
public class LoginHistoryDAO {

    public void record(Integer userId, String usernameAttempted, String status, String detail) {
        String sql = "INSERT INTO login_history (user_id, username_attempted, status, detail) VALUES (?, ?, ?, ?)";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            if (userId == null) {
                ps.setNull(1, Types.INTEGER);
            } else {
                ps.setInt(1, userId);
            }
            ps.setString(2, usernameAttempted);
            ps.setString(3, status);
            ps.setString(4, detail);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException("Could not write login history", e);
        }
    }

    public List<LoginRecord> findByUser(int userId, int limit) {
        return query("SELECT * FROM login_history WHERE user_id = ? ORDER BY history_id DESC LIMIT ?",
                     userId, limit);
    }

    public List<LoginRecord> findRecent(int limit) {
        return query("SELECT * FROM login_history ORDER BY history_id DESC LIMIT ?", limit);
    }

    /** @return {successCount, failureCount} within the last {@code hours} hours */
    public long[] countOutcomesSince(int hours) {
        String sql = "SELECT "
                   + "SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END), "
                   + "SUM(CASE WHEN status <> 'SUCCESS' THEN 1 ELSE 0 END) "
                   + "FROM login_history WHERE attempted_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, hours);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return new long[]{rs.getLong(1), rs.getLong(2)};   // SUM over 0 rows -> NULL -> 0
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not compute login statistics", e);
        }
    }

    private List<LoginRecord> query(String sql, Object... params) {
        List<LoginRecord> out = new ArrayList<>();
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setObject(i + 1, params[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    int uid = rs.getInt("user_id");
                    Integer userId = rs.wasNull() ? null : uid;
                    out.add(new LoginRecord(
                            rs.getLong("history_id"), userId,
                            rs.getString("username_attempted"), rs.getString("status"),
                            rs.getString("detail"),
                            UserDAO.toLdt(rs.getTimestamp("attempted_at"))));
                }
            }
            return out;
        } catch (SQLException e) {
            throw new DataAccessException("Could not read login history", e);
        }
    }
}
