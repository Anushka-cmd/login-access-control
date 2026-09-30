package com.lacms.dao;

import com.lacms.config.DBConnection;
import com.lacms.exception.DataAccessException;
import com.lacms.model.AuditRecord;
import com.lacms.security.InputValidator;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Append-only audit trail of privileged / security-relevant actions. */
public class AuditDAO {

    public void record(String actor, String action, String target, String detail) {
        String sql = "INSERT INTO audit_log (actor_username, action, target_username, detail) VALUES (?, ?, ?, ?)";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, InputValidator.sanitizeForLog(actor, 50));
            ps.setString(2, InputValidator.sanitizeForLog(action, 40));
            ps.setString(3, target == null ? null : InputValidator.sanitizeForLog(target, 50));
            ps.setString(4, InputValidator.sanitizeForLog(detail, 200));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DataAccessException("Could not write audit log", e);
        }
    }

    public List<AuditRecord> findRecent(int limit) {
        List<AuditRecord> out = new ArrayList<>();
        String sql = "SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT ?";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new AuditRecord(
                            rs.getLong("audit_id"), rs.getString("actor_username"),
                            rs.getString("action"), rs.getString("target_username"),
                            rs.getString("detail"),
                            UserDAO.toLdt(rs.getTimestamp("created_at"))));
                }
            }
            return out;
        } catch (SQLException e) {
            throw new DataAccessException("Could not read audit log", e);
        }
    }
}
