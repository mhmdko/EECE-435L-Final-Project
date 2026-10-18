-- =====================================================================
-- 01_users_logs_notifications.sql
-- Tables: users, logs, notifications (+ sample data)
-- Author: Mohammad Kourani
--
-- Run all database scripts with:  python init_db.py
-- Scripts run in name order, so this one runs first: the other teams'
-- tables (assets, incidents, ...) reference users.user_id.
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- users: accounts, login data, roles, and account status
-- ---------------------------------------------------------------------
CREATE TABLE users (
    user_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name        TEXT    NOT NULL,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT    NOT NULL,              -- salted scrypt hash, never the plain password
    department       TEXT    NOT NULL,
    role             TEXT    NOT NULL
        CHECK (role IN ('Security Administrator', 'Security Analyst', 'Regular Employee', 'Auditor')),
    account_status   TEXT    NOT NULL DEFAULT 'Active'
        CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    created_date     DATETIME NOT NULL DEFAULT (datetime('now')),
    last_login_date  DATETIME
);

-- ---------------------------------------------------------------------
-- logs: audit trail of security-relevant activity
-- user_id becomes NULL if the user is deleted, so the record is kept.
-- ---------------------------------------------------------------------
CREATE TABLE logs (
    log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action           TEXT    NOT NULL,
    description      TEXT,
    timestamp        DATETIME NOT NULL DEFAULT (datetime('now')),
    severity         TEXT    NOT NULL DEFAULT 'Information'
        CHECK (severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service  TEXT    NOT NULL
);

CREATE INDEX idx_logs_user_id   ON logs(user_id);
CREATE INDEX idx_logs_timestamp ON logs(timestamp);

-- Audit logs must never be edited. The only change allowed is the automatic
-- one made by ON DELETE SET NULL when the log's user is deleted.
CREATE TRIGGER logs_block_updates
BEFORE UPDATE ON logs
WHEN NOT (
        OLD.user_id IS NOT NULL AND NEW.user_id IS NULL
    AND NEW.log_id = OLD.log_id
    AND NEW.action = OLD.action
    AND NEW.description IS OLD.description
    AND NEW.timestamp = OLD.timestamp
    AND NEW.severity = OLD.severity
    AND NEW.related_service = OLD.related_service
)
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be modified after creation');
END;

-- ---------------------------------------------------------------------
-- notifications: alerts sent to users
-- A user's notifications are deleted together with the user.
-- ---------------------------------------------------------------------
CREATE TABLE notifications (
    notification_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    title              TEXT    NOT NULL,
    message            TEXT    NOT NULL,
    notification_type  TEXT    NOT NULL
        CHECK (notification_type IN ('Incident Assignment', 'Security Alert', 'System Notification',
                                     'Threat Alert', 'Vulnerability Alert')),
    severity           TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status             TEXT    NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
    creation_date      DATETIME NOT NULL DEFAULT (datetime('now')),
    read_date          DATETIME
);

CREATE INDEX idx_notifications_user_id ON notifications(user_id);

-- =====================================================================
-- Sample data
-- Test accounts (one per role, plus two blocked accounts):
--   id  username         password         role                    status
--   1   admin            Admin@1234       Security Administrator  Active
--   2   analyst          Analyst@1234     Security Analyst        Active
--   3   employee         Employee@1234    Regular Employee        Active
--   4   auditor          Auditor@1234     Auditor                 Active
--   5   suspended.user   Suspended@1234   Regular Employee        Suspended
--   6   inactive.user    Inactive@1234    Regular Employee        Inactive
-- These are local test accounts only, not real credentials.
-- =====================================================================

INSERT INTO users (user_id, full_name, username, email, password_hash, department, role, account_status, created_date) VALUES
(1, 'Rana Khalil',  'admin',          'rana.khalil@company.test',  'scrypt:32768:8:1$by7bjcftMdVBqY4s$1a2bc88d9acac83599d06396bb02a840a018af029c42a4bc4b4dc513fb180671bf6b6a89507d2d9ceaa09dab2a72f58077e41b0c99541e9bf73dfbf5fd1c8f9a', 'IT Security', 'Security Administrator', 'Active',    '2026-09-01 08:00:00'),
(2, 'Karim Saad',   'analyst',        'karim.saad@company.test',   'scrypt:32768:8:1$U0QvsPrxnpA07kcq$1983990803ed567688c7248211438553c9c652e36d8b3ecfd99067405d7f37effc781861f7aed67da8507fc4f9c14dc2d7dee99c940bb5fb09ffb0973a4f35ac', 'Security Operations Center', 'Security Analyst', 'Active', '2026-09-01 08:05:00'),
(3, 'Lea Mansour',  'employee',       'lea.mansour@company.test',  'scrypt:32768:8:1$TEgYzzjgyhskggMb$b3090a06ce2fa4f5623e92e7169870b628b84cd3f3480217fd498b3c2ddc0afef1b973850c75e2b4b0c283fe23f323c7b9f7a8032253ba2690a3ac95e3d76092', 'Finance', 'Regular Employee', 'Active',            '2026-09-02 09:00:00'),
(4, 'Omar Fares',   'auditor',        'omar.fares@company.test',   'scrypt:32768:8:1$ljBWXA1qjHIz7Jh7$bd87c115ef9db46ee191ab45de15227997c28a58b85a447c6f3edc0b846a8f5263ac673df866994e5db721e644c86f79d7dc6cdb9dcda8ef33eb1c799cd0d77f', 'Compliance', 'Auditor', 'Active',                   '2026-09-02 09:30:00'),
(5, 'Nadim Aoun',   'suspended.user', 'nadim.aoun@company.test',   'scrypt:32768:8:1$EuT6FJ1i3evI19E4$70219babc962de9008b30f6ff4e0442e45cea383b05d44ae12155d9f3e4a1e6d0a2a00061eca22e76794d85ad57a89a0d7282a668ea56f1fd77464b8b8d83a1f', 'Marketing', 'Regular Employee', 'Suspended',       '2026-09-03 10:00:00'),
(6, 'Maya Azar',    'inactive.user',  'maya.azar@company.test',    'scrypt:32768:8:1$gHWFhrCULP5aEH0D$a7261741c4a247aa25cc85bbd7fedd036b0f9e296d6a1aef16ff37536ab7d95d3a6854ee947ba7ff1977208f7df4d58e0ca578dcbd1e8da749e1ec873b8b9e40', 'Human Resources', 'Regular Employee', 'Inactive', '2026-09-03 10:15:00');

-- Earlier activity, so log searches by date have something to find.
INSERT INTO logs (user_id, action, description, timestamp, severity, related_service) VALUES
(1, 'LOGIN_SUCCESS',       '''admin'' logged in',                                        '2026-10-01 09:15:00', 'Information', 'Users'),
(2, 'LOGIN_FAILED',        'Failed login attempt for ''analyst''',                       '2026-10-01 09:20:00', 'Warning',     'Users'),
(2, 'LOGIN_SUCCESS',       '''analyst'' logged in',                                      '2026-10-01 09:21:00', 'Information', 'Users'),
(1, 'USER_UPDATED',        '''admin'' updated department of user ''employee''',          '2026-10-02 11:00:00', 'Information', 'Users'),
(3, 'UNAUTHORIZED_ACCESS', 'employee (Regular Employee) was denied: User does not have permission to perform this operation (GET /users)', '2026-10-03 14:30:00', 'Warning', 'Users'),
(1, 'ACCOUNT_STATUS_CHANGED', 'Status of ''suspended.user'' changed from Active to Suspended', '2026-10-04 16:45:00', 'Warning', 'Users');

INSERT INTO notifications (user_id, title, message, notification_type, severity, status, creation_date, read_date) VALUES
(3, 'Phishing campaign detected',  'Do not open emails asking you to reset your payroll password.', 'Security Alert',      'High',     'Unread', '2026-10-05 08:30:00', NULL),
(2, 'Incident assigned to you',    'Incident #1 has been assigned to you for investigation.',        'Incident Assignment', 'Medium',   'Unread', '2026-10-05 09:00:00', NULL),
(2, 'Malicious IP added',          'A new malicious IP was added to threat intelligence.',            'Threat Alert',        'Critical', 'Read',   '2026-10-06 10:00:00', '2026-10-06 10:30:00'),
(1, 'Scheduled maintenance',       'The security platform will restart Sunday at 02:00.',             'System Notification', 'Low',      'Read',   '2026-10-06 12:00:00', '2026-10-06 13:00:00');
