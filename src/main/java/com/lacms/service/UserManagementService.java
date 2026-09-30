package com.lacms.service;

import com.lacms.dao.AuditDAO;
import com.lacms.dao.LoginHistoryDAO;
import com.lacms.dao.RoleDAO;
import com.lacms.dao.UserDAO;
import com.lacms.exception.ValidationException;
import com.lacms.model.AuditRecord;
import com.lacms.model.LoginRecord;
import com.lacms.model.User;
import com.lacms.security.InputValidator;
import com.lacms.security.PasswordUtil;
import com.lacms.security.Permissions;
import com.lacms.security.Roles;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Privileged operations. EVERY method starts with acl.require(...), so
 * authorization is enforced here in the service layer, not just by hiding
 * menu items in the UI. A bug in the UI can therefore never grant access.
 */
public class UserManagementService {

    private final UserDAO userDAO;
    private final RoleDAO roleDAO;
    private final LoginHistoryDAO historyDAO;
    private final AuditDAO auditDAO;
    private final AccessControlService acl;

    public UserManagementService(UserDAO userDAO, RoleDAO roleDAO, LoginHistoryDAO historyDAO,
                                 AuditDAO auditDAO, AccessControlService acl) {
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
        this.historyDAO = historyDAO;
        this.auditDAO = auditDAO;
        this.acl = acl;
    }

    // ----------------------------------------------------------- READ
    public User getOwnProfile(User actor) {
        acl.require(actor, Permissions.VIEW_OWN_PROFILE);
        return userDAO.findById(actor.getUserId()).orElseThrow(() -> new ValidationException("Account not found."));
    }

    public List<User> listUsers(User actor) {
        acl.require(actor, Permissions.VIEW_USERS);
        return userDAO.findAll();
    }

    public List<LoginRecord> viewOwnLoginHistory(User actor, int limit) {
        acl.require(actor, Permissions.VIEW_OWN_LOGIN_HISTORY);
        return historyDAO.findByUser(actor.getUserId(), limit);
    }

    public List<LoginRecord> viewAllLoginHistory(User actor, int limit) {
        acl.require(actor, Permissions.VIEW_ALL_LOGIN_HISTORY);
        return historyDAO.findRecent(limit);
    }

    public List<AuditRecord> viewAuditLog(User actor, int limit) {
        acl.require(actor, Permissions.VIEW_AUDIT_LOG);
        return auditDAO.findRecent(limit);
    }

    /** Small security dashboard: who has what role, how many locked, failures in 24h. */
    public Map<String, String> securitySummary(User actor) {
        acl.require(actor, Permissions.VIEW_REPORTS);
        Map<String, String> report = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> e : userDAO.countUsersPerRole().entrySet()) {
            report.put("Users with role " + e.getKey(), String.valueOf(e.getValue()));
        }
        report.put("Currently locked accounts", String.valueOf(userDAO.countLocked()));
        long[] outcomes = historyDAO.countOutcomesSince(24);
        report.put("Successful logins (last 24h)", String.valueOf(outcomes[0]));
        report.put("Failed / blocked logins (last 24h)", String.valueOf(outcomes[1]));
        return report;
    }

    public List<String> listRoles(User actor) {
        acl.require(actor, Permissions.CREATE_USER);
        return roleDAO.findAllRoleNames();
    }

    // ----------------------------------------------------------- CREATE
    public User createUser(User actor, String username, String email, String password, String roleName) {
        acl.require(actor, Permissions.CREATE_USER);
        String uname = username == null ? null : username.trim();
        String mail = email == null ? null : email.trim();
        InputValidator.validateUsername(uname);
        InputValidator.validateEmail(mail);
        InputValidator.validatePassword(password, uname);
        if (roleName == null || !roleDAO.roleExists(roleName)) {
            throw new ValidationException("Unknown role.");
        }
        int id = userDAO.createUser(uname, mail, PasswordUtil.hash(password), roleName);
        auditDAO.record(actor.getUsername(), "USER_CREATED", uname, "Created with role " + roleName);
        return userDAO.findById(id).orElseThrow(() -> new IllegalStateException("User vanished after insert"));
    }

    // ----------------------------------------------------------- UPDATE
    public void changeRole(User actor, int targetId, String newRole) {
        acl.require(actor, Permissions.ASSIGN_ROLE);
        if (actor.getUserId() == targetId) {
            throw new ValidationException("You cannot change your own role.");
        }
        if (newRole == null || !roleDAO.roleExists(newRole)) {
            throw new ValidationException("Unknown role.");
        }
        User target = requireUser(targetId);
        if (Roles.ADMIN.equals(target.getRoleName()) && !Roles.ADMIN.equals(newRole)
                && userDAO.countByRole(Roles.ADMIN) <= 1) {
            throw new ValidationException("Cannot demote the last administrator.");
        }
        userDAO.updateRole(targetId, newRole);
        auditDAO.record(actor.getUsername(), "ROLE_CHANGED", target.getUsername(),
                target.getRoleName() + " -> " + newRole);
    }

    public void unlockAccount(User actor, int targetId) {
        acl.require(actor, Permissions.UNLOCK_ACCOUNT);
        User target = requireUser(targetId);
        if (!target.isLocked()) {
            throw new ValidationException("That account is not locked.");
        }
        userDAO.unlockAccount(targetId);
        auditDAO.record(actor.getUsername(), "ACCOUNT_UNLOCKED", target.getUsername(), "Manual unlock");
    }

    // ----------------------------------------------------------- DELETE
    public void deleteUser(User actor, int targetId) {
        acl.require(actor, Permissions.DELETE_USER);
        if (actor.getUserId() == targetId) {
            throw new ValidationException("You cannot delete your own account.");
        }
        User target = requireUser(targetId);
        if (Roles.ADMIN.equals(target.getRoleName()) && userDAO.countByRole(Roles.ADMIN) <= 1) {
            throw new ValidationException("Cannot delete the last administrator.");
        }
        userDAO.deleteUser(targetId);
        auditDAO.record(actor.getUsername(), "USER_DELETED", target.getUsername(),
                "Deleted account with role " + target.getRoleName());
    }

    private User requireUser(int id) {
        return userDAO.findById(id).orElseThrow(() -> new ValidationException("No user with id " + id + "."));
    }
}
