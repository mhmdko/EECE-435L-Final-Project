-- =====================================================================
-- 03_incidents_playbooks.sql
-- Tables: incidents, investigation_notes, playbooks, response_actions,
--         action_history (+ sample data)
-- Author: Titia Saikali
--
-- Run all database scripts with:  python init_db.py
-- Runs last, because incidents reference users and assets (01 and 02).
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- incidents: cybersecurity incidents and their lifecycle
-- reporter_id: required; a user who reported incidents cannot be deleted.
-- affected_asset_id: an asset with incidents cannot be deleted.
-- assigned_analyst_id: becomes NULL if the analyst's account is deleted.
-- ---------------------------------------------------------------------
CREATE TABLE incidents (
    incident_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title                TEXT    NOT NULL,
    description          TEXT    NOT NULL,
    category             TEXT    NOT NULL
        CHECK (category IN ('Malware Infection', 'Unauthorized Access', 'Phishing Attack', 'Data Leakage',
                            'Account Compromise', 'Denial of Service', 'Other')),
    severity             TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id          INTEGER NOT NULL REFERENCES users(user_id),
    affected_asset_id    INTEGER REFERENCES assets(asset_id),
    assigned_analyst_id  INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    status               TEXT    NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
    created_date         DATETIME NOT NULL DEFAULT (datetime('now')),
    resolution_date      DATETIME,
    updated_date         DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_incidents_reporter_id ON incidents(reporter_id);
CREATE INDEX idx_incidents_asset_id    ON incidents(affected_asset_id);
CREATE INDEX idx_incidents_analyst_id  ON incidents(assigned_analyst_id);

-- ---------------------------------------------------------------------
-- investigation_notes: each note belongs to exactly one incident
-- ---------------------------------------------------------------------
CREATE TABLE investigation_notes (
    note_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id         INTEGER NOT NULL REFERENCES users(user_id),
    note_content       TEXT    NOT NULL,
    created_timestamp  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_notes_incident_id ON investigation_notes(incident_id);

-- ---------------------------------------------------------------------
-- playbooks: standard response procedures, one per category and severity
-- ---------------------------------------------------------------------
CREATE TABLE playbooks (
    playbook_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT    NOT NULL,
    description        TEXT    NOT NULL,
    incident_category  TEXT    NOT NULL
        CHECK (incident_category IN ('Malware Infection', 'Unauthorized Access', 'Phishing Attack', 'Data Leakage',
                                     'Account Compromise', 'Denial of Service', 'Other')),
    severity           TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    created_by         INTEGER NOT NULL REFERENCES users(user_id),
    created_date       DATETIME NOT NULL DEFAULT (datetime('now')),
    CONSTRAINT uq_playbook_category_severity UNIQUE (incident_category, severity)
);

-- ---------------------------------------------------------------------
-- response_actions: the ordered steps of a playbook
-- Deleted together with their playbook. Step numbers are unique per playbook.
-- ---------------------------------------------------------------------
CREATE TABLE response_actions (
    action_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id         INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    action_description  TEXT    NOT NULL,
    step_number         INTEGER NOT NULL CHECK (step_number >= 1),
    status              TEXT    NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id    INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    completion_date     DATETIME,
    created_date        DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_date        DATETIME NOT NULL DEFAULT (datetime('now')),
    CONSTRAINT uq_action_playbook_step UNIQUE (playbook_id, step_number)
);

CREATE INDEX idx_actions_playbook_id ON response_actions(playbook_id);

-- ---------------------------------------------------------------------
-- action_history: every status change of a response action (execution history)
-- ---------------------------------------------------------------------
CREATE TABLE action_history (
    history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id   INTEGER NOT NULL REFERENCES response_actions(action_id) ON DELETE CASCADE,
    old_status  TEXT    NOT NULL,
    new_status  TEXT    NOT NULL,
    changed_by  INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    changed_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_history_action_id ON action_history(action_id);

-- =====================================================================
-- Sample data (users from 01_...sql, assets from 02_...sql)
-- =====================================================================

INSERT INTO incidents (incident_id, title, description, category, severity, reporter_id, affected_asset_id, assigned_analyst_id, status, created_date, resolution_date, updated_date) VALUES
(1, 'Phishing email targeting payroll team', 'Several finance employees received emails asking them to re-enter payroll credentials on a fake portal.', 'Phishing Attack',    'High',     3, 1, 2,    'Under Investigation', '2026-10-01 08:45:00', NULL,                  '2026-10-01 10:00:00'),
(2, 'Ransomware detected on finance laptop',  'Endpoint protection flagged file encryption activity on Finance Laptop 07.',                             'Malware Infection',  'Critical', 3, 3, 2,    'Mitigated',           '2026-10-02 13:10:00', NULL,                  '2026-10-02 18:00:00'),
(3, 'SSH brute-force against core firewall',  'Thousands of failed SSH logins from a Tor exit node within one hour.',                                    'Unauthorized Access','High',     1, 4, 2,    'Resolved',            '2026-10-03 02:30:00', '2026-10-03 09:15:00', '2026-10-03 09:15:00'),
(4, 'HR portal unreachable during peak hours','The HR web portal timed out repeatedly; traffic spikes suggest a denial of service attempt.',             'Denial of Service',  'Medium',   1, 2, NULL, 'Open',                '2026-10-04 11:20:00', NULL,                  '2026-10-04 11:20:00'),
(5, 'Login to mail server from unusual country','A mail account logged in from an unexpected country outside working hours.',                           'Account Compromise', 'Medium',   3, 5, 2,    'Closed',              '2026-10-05 22:05:00', '2026-10-06 12:00:00', '2026-10-07 09:00:00'),
(6, 'Backup bucket publicly readable',        'A misconfigured policy made the backup storage bucket readable from the internet.',                       'Data Leakage',       'Critical', 1, 6, NULL, 'Open',                '2026-10-06 15:40:00', NULL,                  '2026-10-06 15:40:00'),
(7, 'Unapproved browser extension installed', 'A workstation has a browser extension that is not on the approved software list.',                       'Other',              'Low',      3, 7, NULL, 'Open',                '2026-10-07 09:30:00', NULL,                  '2026-10-07 09:30:00');

INSERT INTO investigation_notes (incident_id, analyst_id, note_content, created_timestamp) VALUES
(1, 2, 'Collected email headers: sender domain secure-paypa1-login.com, already listed in threat intelligence.', '2026-10-01 09:30:00'),
(1, 2, 'Blocked the phishing domain on the mail gateway. 3 of 12 recipients clicked the link; resetting their passwords.', '2026-10-01 10:00:00'),
(2, 2, 'Isolated the laptop from the network and captured a memory image for analysis.', '2026-10-02 13:40:00'),
(3, 2, 'Source IP 185.220.101.4 matches a known Tor exit node. Added a geo-block rule on the firewall.', '2026-10-03 03:10:00');

INSERT INTO playbooks (playbook_id, name, description, incident_category, severity, created_by, created_date) VALUES
(1, 'Phishing response, high severity',     'Contain credential phishing campaigns that reached several users.', 'Phishing Attack',     'High',     1, '2026-09-25 09:00:00'),
(2, 'Ransomware containment',               'Stop the spread of ransomware and restore affected systems.',       'Malware Infection',   'Critical', 1, '2026-09-25 09:30:00'),
(3, 'Brute-force attack response',          'Respond to repeated login attempts against exposed services.',      'Unauthorized Access', 'High',     1, '2026-09-26 10:00:00');

INSERT INTO response_actions (action_id, playbook_id, action_description, step_number, status, assigned_user_id, completion_date, created_date, updated_date) VALUES
(1, 1, 'Block the sender domain and URLs on the mail gateway',          1, 'Completed',   2,    '2026-10-01 10:00:00', '2026-09-25 09:05:00', '2026-10-01 10:00:00'),
(2, 1, 'Identify every recipient who clicked the link',                 2, 'In Progress', 2,    NULL,                  '2026-09-25 09:06:00', '2026-10-01 10:05:00'),
(3, 1, 'Reset passwords and revoke sessions for affected users',        3, 'Pending',     NULL, NULL,                  '2026-09-25 09:07:00', '2026-09-25 09:07:00'),
(4, 2, 'Isolate infected machines from the network',                    1, 'Completed',   2,    '2026-10-02 13:40:00', '2026-09-25 09:35:00', '2026-10-02 13:40:00'),
(5, 2, 'Identify the ransomware strain and encryption scope',           2, 'Completed',   2,    '2026-10-02 16:00:00', '2026-09-25 09:36:00', '2026-10-02 16:00:00'),
(6, 2, 'Restore files from clean backups',                              3, 'Pending',     NULL, NULL,                  '2026-09-25 09:37:00', '2026-09-25 09:37:00'),
(7, 3, 'Block the attacking IP addresses at the firewall',              1, 'Pending',     NULL, NULL,                  '2026-09-26 10:05:00', '2026-09-26 10:05:00');

INSERT INTO action_history (action_id, old_status, new_status, changed_by, changed_at) VALUES
(1, 'Pending',     'In Progress', 2, '2026-10-01 09:20:00'),
(1, 'In Progress', 'Completed',   2, '2026-10-01 10:00:00'),
(2, 'Pending',     'In Progress', 2, '2026-10-01 10:05:00'),
(4, 'Pending',     'In Progress', 2, '2026-10-02 13:15:00'),
(4, 'In Progress', 'Completed',   2, '2026-10-02 13:40:00'),
(5, 'Pending',     'In Progress', 2, '2026-10-02 13:45:00'),
(5, 'In Progress', 'Completed',   2, '2026-10-02 16:00:00');
