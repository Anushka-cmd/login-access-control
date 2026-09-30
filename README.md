# Login & Access Control Management System

A backend-focused authentication and role-based access control (RBAC) system
built with **Core Java, JDBC, and MySQL/MariaDB** — no frameworks, so every
piece of the security logic (password hashing, lockout, permission checks,
audit trail) is visible and hand-written rather than hidden inside a library.

## What it does

- **Registration & login** with PBKDF2-hashed passwords (no plaintext or
  reversible encryption anywhere).
- **Role-Based Access Control** for three roles — `ADMIN`, `MANAGER`,
  `EMPLOYEE` — with permissions stored in the database, not hard-coded in
  Java, so what each role can do is data, not code.
- **Account lockout**: 5 failed attempts locks the account; an admin must
  unlock it.
- **Audit trail**: every login attempt (success/failure) and every
  privileged action (role change, unlock, delete, user creation) is logged
  with who did it, to whom, and when.
- **Security summary report**: counts of users per role, locked accounts,
  and login success/failure in the last 24 hours.

## Why it's built this way (talking points for interviews)

| Design choice | Reason |
|---|---|
| `PreparedStatement` everywhere, zero string-concatenated SQL | Eliminates SQL injection by construction |
| PBKDF2-HMAC-SHA256, 600,000 iterations, random salt per user | OWASP-recommended; salted so identical passwords never produce identical hashes |
| Same error message for "no such user" and "wrong password" + constant-time dummy hash check for unknown users | Prevents username enumeration via message *or* response-time differences |
| Permission check re-reads the user's **current** DB state on every call, not the cached session object | A role change or lock takes effect immediately, even for an already-logged-in session |
| Authorization enforced in the **service layer** (`acl.require(...)` at the top of every privileged method) | A bug in the menu/UI can hide an option, but it can never grant access — the real gate is server-side |
| `failed_attempts` increment + lock check wrapped in one DB transaction with `SELECT ... FOR UPDATE` | Two simultaneous bad login attempts can't both slip in under the lockout threshold (race condition) |
| Dedicated `lacms_app` DB user with only `SELECT/INSERT/UPDATE/DELETE`, no DDL | Principle of least privilege — a SQL-injection or app bug can't drop tables |
| Audit/log text run through `sanitizeForLog()` (strips control characters) | Prevents log forging via newline injection in a username |
| "Last admin" guard on delete/demote | Prevents a system from accidentally locking itself out of admin access entirely |

## Project layout

```
db/schema.sql                   Tables, seed roles/permissions, app DB user
src/main/java/com/lacms/
  Main.java                     Console UI — menus built from live permission checks
  config/DBConnection.java      JDBC connection factory (reads env vars)
  security/                     PasswordUtil, InputValidator, Roles/Permissions constants
  model/                        User, LoginRecord, AuditRecord (plain data holders)
  dao/                          UserDAO, RoleDAO, LoginHistoryDAO, AuditDAO — all SQL lives here
  service/                      AuthService (login/lockout), AccessControlService (RBAC),
                                 UserManagementService (admin operations)
  exception/                    ValidationException, AccessDeniedException, etc.
src/test/java/com/lacms/
  PasswordUtilTest.java         Hashing correctness, salting, no-plaintext-leak
  InputValidatorTest.java       Username/email/password rule enforcement
  AccessControlIntegrationTest  End-to-end against a real DB: RBAC, lockout, audit trail
bin/
  build.sh   test.sh   run.sh   Convenience scripts (see below)
```

## Setup

**Requirements:** JDK 17+, MySQL 8.x or MariaDB 10.x, a JDBC driver jar
(`mariadb-java-client` or `mysql-connector-j`).

```bash
# 1. Create the schema, seed roles/permissions, and the app's DB user
mysql -u root -p < db/schema.sql
# then edit the password in db/schema.sql (or ALTER USER afterwards) —
# don't ship the placeholder 'ChangeMe_App#2026' anywhere real.

# 2. Point the app at your database
export LACMS_DB_URL="jdbc:mysql://127.0.0.1:3306/access_control_db"
export LACMS_DB_USER="lacms_app"
export LACMS_DB_PASSWORD="<the password you set>"

# 3. Build and run
bin/build.sh
bin/run.sh
```

First run: since no `ADMIN` exists yet, the app asks you to create one
before showing the login menu. After that, anyone can register (always as
`EMPLOYEE`); only an admin can create `MANAGER`/`ADMIN` accounts or promote
someone.

## Running the tests

```bash
bin/test.sh
```

This compiles and runs 34 tests: unit tests for password hashing and input
validation, plus integration tests that hit a **real** database to prove
role permissions, lockout-after-5-attempts, "locked accounts reject even
the correct password," last-admin protection, and audit logging actually
work end to end (not mocked). The integration tests `TRUNCATE` the
`users`/`login_history`/`audit_log` tables before each test, so point them
at a dev/test database, never production.

## Roles & permissions (seeded by schema.sql)

| Permission | ADMIN | MANAGER | EMPLOYEE |
|---|:---:|:---:|:---:|
| View/edit own profile & password | ✅ | ✅ | ✅ |
| View own login history | ✅ | ✅ | ✅ |
| List all users | ✅ | ✅ | ❌ |
| Security summary report | ✅ | ✅ | ❌ |
| Create users | ✅ | ❌ | ❌ |
| Change a user's role | ✅ | ❌ | ❌ |
| Unlock accounts | ✅ | ❌ | ❌ |
| Delete users | ✅ | ❌ | ❌ |
| View everyone's login history | ✅ | ❌ | ❌ |
| View audit log | ✅ | ❌ | ❌ |

To change what a role can do, edit the `role_permissions` rows in
`db/schema.sql` — no Java code changes needed.

## Known limitations (good to mention as "next steps" in an interview)

- Console app, not a web app — no HTTP layer or REST API yet.
- No session tokens/expiry — the `User session` object lives only for the
  process's lifetime, which is fine for a CLI but not for a real multi-user
  server.
- No email verification or password-reset flow.
- No pagination on `listUsers`/history views — fine at demo scale, would
  need `LIMIT`/`OFFSET` for a large user base.
