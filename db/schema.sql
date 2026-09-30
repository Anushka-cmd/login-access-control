-- =====================================================================
--  Login & Access Control Management System : database schema
--  Works on MySQL 5.7+/8.x and MariaDB 10.x
--  Run:  mysql -u root -p < db/schema.sql
-- =====================================================================
CREATE DATABASE IF NOT EXISTS access_control_db;
USE access_control_db;

-- ---------------------------------------------------------------------
-- Dedicated application user. The app must NEVER connect as root.
-- CHANGE THIS PASSWORD, then set the same value in LACMS_DB_PASSWORD
-- when running the app (see README.md).
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'lacms_app'@'%' IDENTIFIED BY 'ChangeMe_App#2026';
GRANT SELECT, INSERT, UPDATE, DELETE ON access_control_db.* TO 'lacms_app'@'%';
FLUSH PRIVILEGES;

-- ---------- RBAC core ------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    role_id     INT AUTO_INCREMENT PRIMARY KEY,
    role_name   VARCHAR(30)  NOT NULL UNIQUE,
    description VARCHAR(120)
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id   INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(50) NOT NULL UNIQUE,
    description     VARCHAR(120)
);

-- many-to-many: which role holds which permission
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id)       REFERENCES roles(role_id)             ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

-- ---------- Users ----------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id         INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    email           VARCHAR(120) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,          -- pbkdf2_sha256$iterations$salt$hash
    role_id         INT          NOT NULL,
    failed_attempts INT          NOT NULL DEFAULT 0,
    is_locked       BOOLEAN      NOT NULL DEFAULT FALSE,
    locked_at       DATETIME     NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME     NULL,
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- ---------- Audit trails ---------------------------------------------
-- every login attempt (success or failure); user_id kept even if user is
-- later deleted (SET NULL) so the trail is never lost
CREATE TABLE IF NOT EXISTS login_history (
    history_id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id            INT          NULL,
    username_attempted VARCHAR(50)  NOT NULL,
    status             VARCHAR(30)  NOT NULL,
    detail             VARCHAR(200),
    attempted_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_history_user (user_id),
    INDEX idx_history_time (attempted_at)
);

-- privileged / security-relevant actions (role changes, unlocks, deletes...)
-- usernames stored as text on purpose: the record must survive user deletion
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
    actor_username  VARCHAR(50)  NOT NULL,
    action          VARCHAR(40)  NOT NULL,
    target_username VARCHAR(50)  NULL,
    detail          VARCHAR(200),
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_time (created_at)
);

-- ---------- Seed data ------------------------------------------------
INSERT IGNORE INTO roles (role_name, description) VALUES
    ('ADMIN',    'Full control of users, roles and audit data'),
    ('MANAGER',  'Can view users and security reports'),
    ('EMPLOYEE', 'Standard user; own profile only');

INSERT IGNORE INTO permissions (permission_name, description) VALUES
    ('VIEW_OWN_PROFILE',       'View own profile'),
    ('CHANGE_OWN_PASSWORD',    'Change own password'),
    ('VIEW_OWN_LOGIN_HISTORY', 'View own login history'),
    ('VIEW_USERS',             'List all users'),
    ('VIEW_REPORTS',           'View security summary report'),
    ('CREATE_USER',            'Create users with any role'),
    ('ASSIGN_ROLE',            'Change a user''s role'),
    ('UNLOCK_ACCOUNT',         'Unlock locked accounts'),
    ('DELETE_USER',            'Delete users'),
    ('VIEW_ALL_LOGIN_HISTORY', 'View login history of everyone'),
    ('VIEW_AUDIT_LOG',         'View privileged-action audit log');

-- ADMIN gets everything
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id FROM roles r CROSS JOIN permissions p
WHERE r.role_name = 'ADMIN';

-- MANAGER: own-profile permissions + read-only oversight
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id FROM roles r CROSS JOIN permissions p
WHERE r.role_name = 'MANAGER' AND p.permission_name IN
    ('VIEW_OWN_PROFILE','CHANGE_OWN_PASSWORD','VIEW_OWN_LOGIN_HISTORY','VIEW_USERS','VIEW_REPORTS');

-- EMPLOYEE: own data only
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id FROM roles r CROSS JOIN permissions p
WHERE r.role_name = 'EMPLOYEE' AND p.permission_name IN
    ('VIEW_OWN_PROFILE','CHANGE_OWN_PASSWORD','VIEW_OWN_LOGIN_HISTORY');
