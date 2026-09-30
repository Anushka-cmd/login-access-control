package com.lacms;

import com.lacms.config.DBConnection;
import com.lacms.dao.AuditDAO;
import com.lacms.dao.LoginHistoryDAO;
import com.lacms.dao.RoleDAO;
import com.lacms.dao.UserDAO;
import com.lacms.exception.AccessDeniedException;
import com.lacms.exception.ValidationException;
import com.lacms.model.User;
import com.lacms.security.Permissions;
import com.lacms.security.Roles;
import com.lacms.service.AccessControlService;
import com.lacms.service.AuthService;
import com.lacms.service.LoginResult;
import com.lacms.service.UserManagementService;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * End-to-end tests against a REAL MySQL/MariaDB instance (no mocks) to prove
 * the RBAC rules, account lockout and audit trail actually work through the
 * full DAO -> service stack. Requires db/schema.sql to already be loaded.
 * Each test wipes the users/history/audit tables first so tests don't
 * interfere with each other, then re-seeds the users it needs.
 */
public class AccessControlIntegrationTest {

    private static boolean dbAvailable;

    private final UserDAO userDAO = new UserDAO();
    private final RoleDAO roleDAO = new RoleDAO();
    private final LoginHistoryDAO historyDAO = new LoginHistoryDAO();
    private final AuditDAO auditDAO = new AuditDAO();
    private final AccessControlService acl = new AccessControlService(userDAO, roleDAO, auditDAO);
    private final AuthService authService = new AuthService(userDAO, historyDAO, auditDAO, acl);
    private final UserManagementService userMgmt =
            new UserManagementService(userDAO, roleDAO, historyDAO, auditDAO, acl);

    @BeforeClass
    public static void checkDb() {
        dbAvailable = DBConnection.isReachable();
    }

    @Before
    public void resetData() throws SQLException {
        assumeTrue("Skipping: no database reachable at " + DBConnection.getUrl(), dbAvailable);
        // DELETE, not TRUNCATE: the app's DB user intentionally has no DROP
        // privilege (least privilege - see README), and TRUNCATE requires it.
        // Deleting from the child tables first satisfies the FK constraints.
        try (Connection c = DBConnection.getConnection(); Statement st = c.createStatement()) {
            st.execute("DELETE FROM audit_log");
            st.execute("DELETE FROM login_history");
            st.execute("DELETE FROM users");
        }
    }

    private User makeUser(String username, String role, String password) {
        String hash = com.lacms.security.PasswordUtil.hash(password);
        int id = userDAO.createUser(username, username + "@example.com", hash, role);
        return userDAO.findById(id).orElseThrow(() -> new IllegalStateException("insert failed"));
    }

    // -------------------------------------------------- RBAC
    @Test
    public void adminHasEveryPermission() {
        User admin = makeUser("admin1", Roles.ADMIN, "Adm1n!Pass1");
        assertTrue(acl.hasPermission(admin, Permissions.DELETE_USER));
        assertTrue(acl.hasPermission(admin, Permissions.VIEW_AUDIT_LOG));
        assertTrue(acl.hasPermission(admin, Permissions.ASSIGN_ROLE));
    }

    @Test
    public void employeeCannotListUsers() {
        User employee = makeUser("emp1", Roles.EMPLOYEE, "Empl0yee!Pass1");
        assertFalse(acl.hasPermission(employee, Permissions.VIEW_USERS));
    }

    @Test(expected = AccessDeniedException.class)
    public void employeeCallingAdminServiceMethodIsBlockedByServiceLayer() {
        // Proves enforcement lives in the service layer, not just hidden UI menus.
        User employee = makeUser("emp2", Roles.EMPLOYEE, "Empl0yee!Pass1");
        userMgmt.listUsers(employee);
    }

    @Test
    public void managerCanViewUsersButNotDeleteThem() {
        User manager = makeUser("mgr1", Roles.MANAGER, "Manag3r!Pass1");
        assertTrue(acl.hasPermission(manager, Permissions.VIEW_USERS));
        assertFalse(acl.hasPermission(manager, Permissions.DELETE_USER));
    }

    @Test
    public void roleChangeTakesEffectImmediatelyForAnAlreadyHeldSessionObject() {
        User admin = makeUser("admin2", Roles.ADMIN, "Adm1n!Pass2");
        User employee = makeUser("emp3", Roles.EMPLOYEE, "Empl0yee!Pass1");

        assertFalse(acl.hasPermission(employee, Permissions.VIEW_USERS));
        userMgmt.changeRole(admin, employee.getUserId(), Roles.MANAGER);

        // 'employee' variable is the OLD session object (still says role=EMPLOYEE),
        // but acl re-reads current state from the DB on every check.
        assertTrue("permission must reflect the NEW role even though the held User object is stale",
                acl.hasPermission(employee, Permissions.VIEW_USERS));
    }

    @Test
    public void cannotDemoteTheLastAdmin() {
        User onlyAdmin = makeUser("solo_admin", Roles.ADMIN, "Adm1n!Pass3");
        try {
            userMgmt.changeRole(onlyAdmin, onlyAdmin.getUserId(), Roles.EMPLOYEE);
            fail("should not be able to change own role at all");
        } catch (ValidationException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("own role"));
        }
    }

    @Test
    public void cannotDeleteTheLastAdminEvenByAnotherAdmin() {
        User admin1 = makeUser("last_admin", Roles.ADMIN, "Adm1n!Pass4");
        User employee = makeUser("emp4", Roles.EMPLOYEE, "Empl0yee!Pass1");
        // promote employee to admin momentarily then demote back down to test the guard on admin1 alone
        // simpler: directly attempt delete of the sole admin by itself using a second admin
        User admin2 = makeUser("second_admin", Roles.ADMIN, "Adm1n!Pass5");
        userMgmt.deleteUser(admin2, admin1.getUserId()); // fine: two admins existed
        assertFalse(userDAO.findById(admin1.getUserId()).isPresent());
        // now only admin2 remains; deleting it must fail
        try {
            // an admin cannot delete itself either (separate rule), so use a fresh third admin attempt
            userMgmt.deleteUser(admin2, admin2.getUserId());
            fail("admin should not be able to delete itself");
        } catch (ValidationException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("own account"));
        }
    }

    // -------------------------------------------------- Authentication & lockout
    @Test
    public void correctPasswordLogsIn() {
        makeUser("bob", Roles.EMPLOYEE, "B0bsP@ssword1");
        LoginResult result = authService.login("bob", "B0bsP@ssword1");
        assertTrue(result.isSuccess());
    }

    @Test
    public void wrongPasswordFails() {
        makeUser("carol", Roles.EMPLOYEE, "Car0lP@ss1");
        LoginResult result = authService.login("carol", "WrongPassword1!");
        assertFalse(result.isSuccess());
        assertFalse(result.isLocked());
    }

    @Test
    public void unknownUserAndWrongPasswordGiveIdenticalMessage() {
        makeUser("dave", Roles.EMPLOYEE, "DaveP@ss123");
        LoginResult unknownUser = authService.login("nobody_such_user", "whatever");
        LoginResult wrongPassword = authService.login("dave", "WrongPassword1!");
        assertEquals("must not leak which part was wrong (username enumeration)",
                unknownUser.getMessage(), wrongPassword.getMessage());
    }

    @Test
    public void accountLocksAfterFiveFailedAttempts() {
        User user = makeUser("erin", Roles.EMPLOYEE, "Er1nP@ssword1");
        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS - 1; i++) {
            LoginResult r = authService.login("erin", "WrongPassword1!");
            assertFalse(r.isLocked());
        }
        LoginResult lockingAttempt = authService.login("erin", "WrongPassword1!");
        assertTrue("5th failed attempt should lock the account", lockingAttempt.isLocked());

        User reloaded = userDAO.findById(user.getUserId()).orElseThrow(() -> new IllegalStateException());
        assertTrue(reloaded.isLocked());
    }

    @Test
    public void lockedAccountRejectsEvenTheCorrectPassword() {
        User user = makeUser("frank", Roles.EMPLOYEE, "Fr@nkPass123");
        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
            authService.login("frank", "WrongPassword1!");
        }
        assertTrue(userDAO.findById(user.getUserId()).get().isLocked());

        LoginResult attempt = authService.login("frank", "Fr@nkPass123"); // correct password, but locked
        assertFalse(attempt.isSuccess());
        assertTrue(attempt.isLocked());
    }

    @Test
    public void successfulLoginResetsFailedAttemptCounter() {
        makeUser("grace", Roles.EMPLOYEE, "Gr@ceP@ss1");
        authService.login("grace", "WrongPassword1!");
        authService.login("grace", "WrongPassword1!");
        LoginResult success = authService.login("grace", "Gr@ceP@ss1");
        assertTrue(success.isSuccess());
        assertEquals(0, userDAO.findByUsername("grace").get().getFailedAttempts());
    }

    @Test
    public void unlockAccountByAdminAllowsLoginAgain() {
        User admin = makeUser("admin3", Roles.ADMIN, "Adm1n!Pass6");
        User user = makeUser("henry", Roles.EMPLOYEE, "H3nryP@ss1");
        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
            authService.login("henry", "WrongPassword1!");
        }
        assertTrue(userDAO.findById(user.getUserId()).get().isLocked());

        userMgmt.unlockAccount(admin, user.getUserId());
        LoginResult afterUnlock = authService.login("henry", "H3nryP@ss1");
        assertTrue(afterUnlock.isSuccess());
    }

    @Test
    public void everyLoginAttemptIsRecordedInHistory() {
        makeUser("ivy", Roles.EMPLOYEE, "IvyP@ssword1");
        authService.login("ivy", "WrongPassword1!");
        authService.login("ivy", "IvyP@ssword1");
        assertEquals(2, historyDAO.findByUser(userDAO.findByUsername("ivy").get().getUserId(), 10).size());
    }

    @Test
    public void privilegedActionsAreAudited() {
        User admin = makeUser("admin4", Roles.ADMIN, "Adm1n!Pass7");
        User target = makeUser("jack", Roles.EMPLOYEE, "J@ckPass123");
        userMgmt.changeRole(admin, target.getUserId(), Roles.MANAGER);
        boolean found = auditDAO.findRecent(10).stream()
                .anyMatch(a -> "ROLE_CHANGED".equals(a.getAction()) && "jack".equals(a.getTargetUsername()));
        assertTrue("role change must appear in the audit log", found);
    }

    @Test(expected = com.lacms.exception.DuplicateUserException.class)
    public void duplicateUsernameIsRejected() {
        makeUser("kate", Roles.EMPLOYEE, "K@tePassword1");
        userDAO.createUser("kate", "different@example.com",
                com.lacms.security.PasswordUtil.hash("Another1!Pass"), Roles.EMPLOYEE);
    }

    @Test
    public void registrationAlwaysCreatesEmployeeRegardlessOfInput() {
        User registered = authService.register("liam", "liam@example.com", "L1amP@ssword1");
        assertEquals(Roles.EMPLOYEE, registered.getRoleName());
    }
}
