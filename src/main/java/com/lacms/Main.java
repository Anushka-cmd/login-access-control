package com.lacms;

import com.lacms.config.DBConnection;
import com.lacms.dao.AuditDAO;
import com.lacms.dao.LoginHistoryDAO;
import com.lacms.dao.RoleDAO;
import com.lacms.dao.UserDAO;
import com.lacms.exception.AccessDeniedException;
import com.lacms.exception.DataAccessException;
import com.lacms.exception.DuplicateUserException;
import com.lacms.exception.ValidationException;
import com.lacms.model.AuditRecord;
import com.lacms.model.LoginRecord;
import com.lacms.model.User;
import com.lacms.security.Permissions;
import com.lacms.security.Roles;
import com.lacms.service.AccessControlService;
import com.lacms.service.AuthService;
import com.lacms.service.LoginResult;
import com.lacms.service.UserManagementService;

import java.io.Console;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Console front-end for the Login & Access Control Management System.
 * Every menu is built from permission checks, not hard-coded role names,
 * so the UI automatically matches whatever the database says the user
 * is allowed to do.
 */
public class Main {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private final Scanner in = new Scanner(System.in);

    private final UserDAO userDAO = new UserDAO();
    private final RoleDAO roleDAO = new RoleDAO();
    private final LoginHistoryDAO historyDAO = new LoginHistoryDAO();
    private final AuditDAO auditDAO = new AuditDAO();
    private final AccessControlService acl = new AccessControlService(userDAO, roleDAO, auditDAO);
    private final AuthService authService = new AuthService(userDAO, historyDAO, auditDAO, acl);
    private final UserManagementService userMgmt =
            new UserManagementService(userDAO, roleDAO, historyDAO, auditDAO, acl);

    private User session;

    public static void main(String[] args) {
        new Main().run();
    }

    private void run() {
        System.out.println("==========================================================");
        System.out.println(" Login & Access Control Management System");
        System.out.println("==========================================================");

        if (!DBConnection.isReachable()) {
            System.out.println("Cannot reach the database at " + DBConnection.getUrl());
            System.out.println("Check LACMS_DB_URL / LACMS_DB_USER / LACMS_DB_PASSWORD and that");
            System.out.println("db/schema.sql has been loaded, then try again.");
            return;
        }

        if (userDAO.countByRole(Roles.ADMIN) == 0) {
            System.out.println("\nNo administrator exists yet. Let's create the first one.");
            bootstrapAdmin();
        }

        while (true) {
            System.out.println();
            System.out.println("1) Login   2) Register (Employee)   3) Exit");
            switch (prompt("Choose an option: ")) {
                case "1": doLogin(); break;
                case "2": doRegister(); break;
                case "3": System.out.println("Goodbye."); return;
                default: System.out.println("Please enter 1, 2 or 3.");
            }
            if (session != null) {
                sessionLoop();
            }
        }
    }

    // ------------------------------------------------------------ bootstrap / auth
    private void bootstrapAdmin() {
        try {
            String username = prompt("Admin username: ");
            String email = prompt("Admin email: ");
            String password = promptPassword("Admin password: ");
            User admin = authService.createInitialAdmin(username, email, password);
            System.out.println("Administrator '" + admin.getUsername() + "' created. Please log in.");
        } catch (ValidationException | DuplicateUserException e) {
            System.out.println("Could not create admin: " + e.getMessage());
        }
    }

    private void doLogin() {
        String username = prompt("Username: ");
        String password = promptPassword("Password: ");
        LoginResult result = authService.login(username, password);
        System.out.println(result.getMessage());
        if (result.isSuccess()) {
            session = result.getUser();
            System.out.println("Welcome, " + session.getUsername() + " (" + session.getRoleName() + ").");
        }
    }

    private void doRegister() {
        try {
            String username = prompt("Choose a username: ");
            String email = prompt("Email: ");
            System.out.println("Password needs 8+ chars with upper, lower, digit and symbol.");
            String password = promptPassword("Choose a password: ");
            User user = authService.register(username, email, password);
            System.out.println("Account '" + user.getUsername() + "' created as EMPLOYEE. You can now log in.");
        } catch (ValidationException | DuplicateUserException e) {
            System.out.println("Registration failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------ main session menu
    private void sessionLoop() {
        while (session != null) {
            System.out.println("\n--- Menu (" + session.getUsername() + " / " + session.getRoleName() + ") ---");
            int n = 1;
            if (acl.hasPermission(session, Permissions.VIEW_OWN_PROFILE))       System.out.println((n++) + ") My profile");
            if (acl.hasPermission(session, Permissions.CHANGE_OWN_PASSWORD))    System.out.println((n++) + ") Change my password");
            if (acl.hasPermission(session, Permissions.VIEW_OWN_LOGIN_HISTORY))System.out.println((n++) + ") My login history");
            if (acl.hasPermission(session, Permissions.VIEW_USERS))            System.out.println((n++) + ") List all users");
            if (acl.hasPermission(session, Permissions.VIEW_REPORTS))          System.out.println((n++) + ") Security summary report");
            if (acl.hasPermission(session, Permissions.CREATE_USER))           System.out.println((n++) + ") Create a user");
            if (acl.hasPermission(session, Permissions.ASSIGN_ROLE))           System.out.println((n++) + ") Change a user's role");
            if (acl.hasPermission(session, Permissions.UNLOCK_ACCOUNT))        System.out.println((n++) + ") Unlock an account");
            if (acl.hasPermission(session, Permissions.DELETE_USER))           System.out.println((n++) + ") Delete a user");
            if (acl.hasPermission(session, Permissions.VIEW_ALL_LOGIN_HISTORY))System.out.println((n++) + ") View all login history");
            if (acl.hasPermission(session, Permissions.VIEW_AUDIT_LOG))        System.out.println((n++) + ") View audit log");
            int logoutOption = n;
            System.out.println(logoutOption + ") Logout");

            String choice = prompt("Choose an option: ");
            try {
                dispatch(choice, logoutOption);
            } catch (AccessDeniedException | ValidationException | DataAccessException e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    /**
     * Menu numbers are assigned dynamically based on permissions, so we
     * re-derive what each number means rather than hard-coding positions.
     * This keeps the menu itself from being a source of truth for access;
     * every action still goes through acl.require(...) in the service layer.
     */
    private void dispatch(String choice, int logoutOption) {
        int selected;
        try {
            selected = Integer.parseInt(choice);
        } catch (NumberFormatException e) {
            System.out.println("Please enter a number.");
            return;
        }
        if (selected == logoutOption) {
            System.out.println("Logged out.");
            session = null;
            return;
        }
        int n = 1;
        if (acl.hasPermission(session, Permissions.VIEW_OWN_PROFILE) && selected == n++) { showProfile(); return; }
        if (acl.hasPermission(session, Permissions.CHANGE_OWN_PASSWORD) && selected == n++) { changePassword(); return; }
        if (acl.hasPermission(session, Permissions.VIEW_OWN_LOGIN_HISTORY) && selected == n++) { showOwnHistory(); return; }
        if (acl.hasPermission(session, Permissions.VIEW_USERS) && selected == n++) { listUsers(); return; }
        if (acl.hasPermission(session, Permissions.VIEW_REPORTS) && selected == n++) { showReport(); return; }
        if (acl.hasPermission(session, Permissions.CREATE_USER) && selected == n++) { createUser(); return; }
        if (acl.hasPermission(session, Permissions.ASSIGN_ROLE) && selected == n++) { changeRole(); return; }
        if (acl.hasPermission(session, Permissions.UNLOCK_ACCOUNT) && selected == n++) { unlockAccount(); return; }
        if (acl.hasPermission(session, Permissions.DELETE_USER) && selected == n++) { deleteUser(); return; }
        if (acl.hasPermission(session, Permissions.VIEW_ALL_LOGIN_HISTORY) && selected == n++) { showAllHistory(); return; }
        if (acl.hasPermission(session, Permissions.VIEW_AUDIT_LOG) && selected == n++) { showAuditLog(); return; }
        System.out.println("Invalid option.");
    }

    // ------------------------------------------------------------ actions
    private void showProfile() {
        User u = userMgmt.getOwnProfile(session);
        System.out.println("Username : " + u.getUsername());
        System.out.println("Email    : " + u.getEmail());
        System.out.println("Role     : " + u.getRoleName());
        System.out.println("Created  : " + fmt(u.getCreatedAt()));
        System.out.println("Last login: " + fmt(u.getLastLoginAt()));
    }

    private void changePassword() {
        String current = promptPassword("Current password: ");
        String next = promptPassword("New password: ");
        authService.changePassword(session, current, next);
        System.out.println("Password updated.");
    }

    private void showOwnHistory() {
        List<LoginRecord> records = userMgmt.viewOwnLoginHistory(session, 10);
        printHistory(records);
    }

    private void listUsers() {
        List<User> users = userMgmt.listUsers(session);
        System.out.printf("%-5s %-15s %-25s %-10s %-8s%n", "ID", "Username", "Email", "Role", "Locked");
        for (User u : users) {
            System.out.printf("%-5d %-15s %-25s %-10s %-8s%n",
                    u.getUserId(), u.getUsername(), u.getEmail(), u.getRoleName(), u.isLocked() ? "YES" : "no");
        }
    }

    private void showReport() {
        Map<String, String> report = userMgmt.securitySummary(session);
        report.forEach((k, v) -> System.out.println(k + ": " + v));
    }

    private void createUser() {
        List<String> roles = userMgmt.listRoles(session);
        String username = prompt("New username: ");
        String email = prompt("New user email: ");
        String password = promptPassword("Temporary password: ");
        String role = prompt("Role " + roles + ": ");
        User created = userMgmt.createUser(session, username, email, password, role);
        System.out.println("Created user '" + created.getUsername() + "' with role " + created.getRoleName() + ".");
    }

    private void changeRole() {
        int id = promptInt("Target user id: ");
        List<String> roles = userMgmt.listRoles(session);
        String role = prompt("New role " + roles + ": ");
        userMgmt.changeRole(session, id, role);
        System.out.println("Role updated.");
    }

    private void unlockAccount() {
        int id = promptInt("User id to unlock: ");
        userMgmt.unlockAccount(session, id);
        System.out.println("Account unlocked.");
    }

    private void deleteUser() {
        int id = promptInt("User id to delete: ");
        String confirm = prompt("Type YES to confirm deletion: ");
        if (!"YES".equals(confirm)) {
            System.out.println("Cancelled.");
            return;
        }
        userMgmt.deleteUser(session, id);
        System.out.println("User deleted.");
    }

    private void showAllHistory() {
        printHistory(userMgmt.viewAllLoginHistory(session, 20));
    }

    private void showAuditLog() {
        List<AuditRecord> records = userMgmt.viewAuditLog(session, 20);
        System.out.printf("%-20s %-12s %-18s %-15s %s%n", "When", "Actor", "Action", "Target", "Detail");
        for (AuditRecord r : records) {
            System.out.printf("%-20s %-12s %-18s %-15s %s%n",
                    fmt(r.getCreatedAt()), r.getActorUsername(), r.getAction(),
                    r.getTargetUsername() == null ? "-" : r.getTargetUsername(), r.getDetail());
        }
    }

    private void printHistory(List<LoginRecord> records) {
        System.out.printf("%-20s %-15s %-22s %s%n", "When", "Username", "Status", "Detail");
        for (LoginRecord r : records) {
            System.out.printf("%-20s %-15s %-22s %s%n",
                    fmt(r.getAttemptedAt()), r.getUsernameAttempted(), r.getStatus(),
                    r.getDetail() == null ? "-" : r.getDetail());
        }
    }

    // ------------------------------------------------------------ input helpers
    private String prompt(String label) {
        System.out.print(label);
        if (!in.hasNextLine()) {
            // stdin closed (piped input ended, Ctrl-D, etc.) -> exit cleanly, no stack trace
            System.out.println("\nInput closed. Exiting.");
            System.exit(0);
        }
        return in.nextLine().trim();
    }

    private String promptPassword(String label) {
        Console console = System.console();
        System.out.print(label);
        if (console != null) {
            char[] chars = console.readPassword();
            return chars == null ? "" : new String(chars);
        }
        // no controlling terminal (IDE run / piped input) -> fall back to visible input
        return in.nextLine();
    }

    private int promptInt(String label) {
        while (true) {
            try {
                return Integer.parseInt(prompt(label));
            } catch (NumberFormatException e) {
                System.out.println("Please enter a whole number.");
            }
        }
    }

    private static String fmt(java.time.LocalDateTime t) {
        return t == null ? "never" : t.format(FMT);
    }
}
