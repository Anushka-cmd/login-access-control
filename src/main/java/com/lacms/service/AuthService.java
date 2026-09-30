package com.lacms.service;

import com.lacms.dao.AuditDAO;
import com.lacms.dao.LoginHistoryDAO;
import com.lacms.dao.UserDAO;
import com.lacms.exception.ValidationException;
import com.lacms.model.User;
import com.lacms.security.InputValidator;
import com.lacms.security.LoginStatus;
import com.lacms.security.PasswordUtil;
import com.lacms.security.Permissions;
import com.lacms.security.Roles;

import java.util.Optional;

/** Registration, login (with lockout) and password change. */
public class AuthService {

    public static final int MAX_FAILED_ATTEMPTS = 5;

    /** Same text for "no such user" and "wrong password" -> no username enumeration. */
    static final String GENERIC_FAILURE = "Invalid username or password.";
    static final String LOCKED_MESSAGE =
            "This account is locked after too many failed attempts. Please contact an administrator.";

    private final UserDAO userDAO;
    private final LoginHistoryDAO historyDAO;
    private final AuditDAO auditDAO;
    private final AccessControlService acl;

    public AuthService(UserDAO userDAO, LoginHistoryDAO historyDAO, AuditDAO auditDAO,
                       AccessControlService acl) {
        this.userDAO = userDAO;
        this.historyDAO = historyDAO;
        this.auditDAO = auditDAO;
        this.acl = acl;
    }

    /** Public self-registration. ALWAYS creates an EMPLOYEE: nobody can register as admin. */
    public User register(String username, String email, String password) {
        String uname = username == null ? null : username.trim();
        String mail = email == null ? null : email.trim();
        InputValidator.validateUsername(uname);
        InputValidator.validateEmail(mail);
        InputValidator.validatePassword(password, uname);

        int id = userDAO.createUser(uname, mail, PasswordUtil.hash(password), Roles.EMPLOYEE);
        auditDAO.record(uname, "USER_REGISTERED", uname, "Self-registration as EMPLOYEE");
        return userDAO.findById(id).orElseThrow(() -> new IllegalStateException("User vanished after insert"));
    }

    /** First-run bootstrap: only works while no ADMIN exists yet. */
    public User createInitialAdmin(String username, String email, String password) {
        if (userDAO.countByRole(Roles.ADMIN) > 0) {
            throw new IllegalStateException("An administrator already exists.");
        }
        String uname = username == null ? null : username.trim();
        String mail = email == null ? null : email.trim();
        InputValidator.validateUsername(uname);
        InputValidator.validateEmail(mail);
        InputValidator.validatePassword(password, uname);

        int id = userDAO.createUser(uname, mail, PasswordUtil.hash(password), Roles.ADMIN);
        auditDAO.record("SYSTEM", "INITIAL_ADMIN_CREATED", uname, "First-run setup");
        return userDAO.findById(id).orElseThrow(() -> new IllegalStateException("User vanished after insert"));
    }

    public LoginResult login(String username, String password) {
        String uname = username == null ? "" : username.trim();
        String pw = password == null ? "" : password;
        String loggedName = InputValidator.sanitizeForLog(uname, 50);

        Optional<User> found = uname.isEmpty() ? Optional.<User>empty() : userDAO.findByUsername(uname);

        // 1) unknown user: burn the same CPU time as a real check, return generic message
        if (!found.isPresent()) {
            PasswordUtil.burnTime(pw);
            historyDAO.record(null, loggedName, LoginStatus.FAILED_UNKNOWN_USER, "No such user");
            return LoginResult.failure(GENERIC_FAILURE);
        }
        User user = found.get();

        // 2) already locked: refuse WITHOUT checking the password
        if (user.isLocked()) {
            historyDAO.record(user.getUserId(), user.getUsername(), LoginStatus.BLOCKED_LOCKED,
                    "Attempt on locked account");
            return LoginResult.locked(LOCKED_MESSAGE);
        }

        // 3) correct password
        if (PasswordUtil.verify(pw, user.getPasswordHash())) {
            userDAO.recordSuccessfulLogin(user.getUserId());
            historyDAO.record(user.getUserId(), user.getUsername(), LoginStatus.SUCCESS, null);
            User fresh = userDAO.findById(user.getUserId()).orElse(user);
            return LoginResult.success(fresh);
        }

        // 4) wrong password: count it, lock at the threshold
        UserDAO.AttemptResult result = userDAO.recordFailedAttempt(user.getUserId(), MAX_FAILED_ATTEMPTS);
        if (result.lockedNow) {
            historyDAO.record(user.getUserId(), user.getUsername(), LoginStatus.ACCOUNT_LOCKED,
                    "Locked after " + result.attempts + " failed attempts");
            auditDAO.record("SYSTEM", "ACCOUNT_LOCKED", user.getUsername(),
                    "Locked after " + result.attempts + " failed attempts");
            return LoginResult.locked(LOCKED_MESSAGE);
        }
        historyDAO.record(user.getUserId(), user.getUsername(), LoginStatus.FAILED_BAD_PASSWORD,
                "Failed attempt " + result.attempts + " of " + MAX_FAILED_ATTEMPTS);
        return LoginResult.failure(GENERIC_FAILURE);
    }

    /** A logged-in user changes their own password (must re-enter the current one). */
    public void changePassword(User actor, String currentPassword, String newPassword) {
        acl.require(actor, Permissions.CHANGE_OWN_PASSWORD);
        User current = userDAO.findById(actor.getUserId())
                .orElseThrow(() -> new ValidationException("Account no longer exists."));

        if (!PasswordUtil.verify(currentPassword, current.getPasswordHash())) {
            // a stolen session must not be able to brute-force the current password
            UserDAO.AttemptResult r = userDAO.recordFailedAttempt(current.getUserId(), MAX_FAILED_ATTEMPTS);
            historyDAO.record(current.getUserId(), current.getUsername(), LoginStatus.FAILED_BAD_PASSWORD,
                    "Wrong current password during password change");
            if (r.lockedNow) {
                auditDAO.record("SYSTEM", "ACCOUNT_LOCKED", current.getUsername(),
                        "Locked during password change attempts");
                throw new ValidationException("Too many failures. Your account has been locked.");
            }
            throw new ValidationException("Current password is incorrect.");
        }
        if (currentPassword.equals(newPassword)) {
            throw new ValidationException("New password must differ from the current password.");
        }
        InputValidator.validatePassword(newPassword, current.getUsername());

        userDAO.updatePassword(current.getUserId(), PasswordUtil.hash(newPassword));
        auditDAO.record(current.getUsername(), "PASSWORD_CHANGED", current.getUsername(), "Self-service change");
    }
}
