package com.lacms.service;

import com.lacms.dao.AuditDAO;
import com.lacms.dao.RoleDAO;
import com.lacms.dao.UserDAO;
import com.lacms.exception.AccessDeniedException;
import com.lacms.model.User;

import java.util.Optional;

/**
 * The single gatekeeper for authorization (RBAC).
 *
 * Permissions are re-read from the database on EVERY check using the
 * user's CURRENT state, not the copy held in the session. So if an admin
 * changes a role, locks or deletes an account, the change takes effect on
 * the very next action, even for someone who is already logged in.
 */
public class AccessControlService {

    private final UserDAO userDAO;
    private final RoleDAO roleDAO;
    private final AuditDAO auditDAO;

    public AccessControlService(UserDAO userDAO, RoleDAO roleDAO, AuditDAO auditDAO) {
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
        this.auditDAO = auditDAO;
    }

    public boolean hasPermission(User actor, String permission) {
        if (actor == null) {
            return false;
        }
        Optional<User> current = userDAO.findById(actor.getUserId());
        if (!current.isPresent() || current.get().isLocked()) {
            return false;                       // deleted or locked -> no privileges at all
        }
        return roleDAO.roleHasPermission(current.get().getRoleId(), permission);
    }

    /** Throws (and audits) when the permission is missing. */
    public void require(User actor, String permission) {
        if (!hasPermission(actor, permission)) {
            auditDAO.record(actor == null ? "anonymous" : actor.getUsername(),
                    "ACCESS_DENIED", null, "Missing permission " + permission);
            throw new AccessDeniedException("Access denied: you need the " + permission + " permission.");
        }
    }
}
