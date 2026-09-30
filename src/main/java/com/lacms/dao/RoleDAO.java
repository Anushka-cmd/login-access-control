package com.lacms.dao;

import com.lacms.config.DBConnection;
import com.lacms.exception.DataAccessException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Reads the role / permission tables. */
public class RoleDAO {

    public boolean roleHasPermission(int roleId, String permissionName) {
        String sql = "SELECT 1 FROM role_permissions rp "
                   + "JOIN permissions p ON rp.permission_id = p.permission_id "
                   + "WHERE rp.role_id = ? AND p.permission_name = ?";
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, roleId);
            ps.setString(2, permissionName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not check permission", e);
        }
    }

    public List<String> findAllRoleNames() {
        List<String> names = new ArrayList<>();
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT role_name FROM roles ORDER BY role_id");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                names.add(rs.getString(1));
            }
            return names;
        } catch (SQLException e) {
            throw new DataAccessException("Could not list roles", e);
        }
    }

    public boolean roleExists(String roleName) {
        try (Connection c = DBConnection.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT 1 FROM roles WHERE role_name = ?")) {
            ps.setString(1, roleName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new DataAccessException("Could not check role", e);
        }
    }
}
