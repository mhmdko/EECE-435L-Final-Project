-- =====================================================================
-- 02_assets_threats_vulnerabilities.sql
-- Tables: assets, threats, vulnerabilities (+ sample data)
-- Author: Anthony Feghali
--
-- Run all database scripts with:  python init_db.py
-- Runs after 01_users_logs_notifications.sql, because assets.owner_id
-- references users.user_id. The Incidents service (03_...) references assets.
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- assets: organizational assets that incidents and vulnerabilities affect
-- A user who still owns assets cannot be deleted (no ON DELETE action).
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT    NOT NULL,
    asset_type        TEXT    NOT NULL
        CHECK (asset_type IN ('Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource')),
    ip_address        TEXT    NOT NULL,
    operating_system  TEXT,
    department        TEXT    NOT NULL,
    owner_id          INTEGER NOT NULL REFERENCES users(user_id),
    location          TEXT,
    criticality       TEXT    NOT NULL CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT    NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Inactive', 'Under Maintenance')),
    created_date      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_date      DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_assets_owner_id ON assets(owner_id);

-- ---------------------------------------------------------------------
-- threats: threat intelligence indicators
-- The same (threat_type, threat_value) pair cannot be stored twice.
-- ---------------------------------------------------------------------
CREATE TABLE threats (
    threat_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type   TEXT    NOT NULL
        CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other')),
    threat_value  TEXT    NOT NULL,
    description   TEXT    NOT NULL,
    severity      TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source        TEXT    NOT NULL,
    date_added    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_date  DATETIME NOT NULL DEFAULT (datetime('now')),
    CONSTRAINT uq_threat_type_value UNIQUE (threat_type, threat_value)
);

-- ---------------------------------------------------------------------
-- vulnerabilities: weaknesses found on assets
-- Each vulnerability belongs to exactly one asset. An asset that still has
-- vulnerabilities cannot be deleted (no ON DELETE action).
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    vulnerability_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT    NOT NULL,
    description       TEXT    NOT NULL,
    cve_id            TEXT    NOT NULL,
    cvss_score        REAL    NOT NULL CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
    severity          TEXT    NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    asset_id          INTEGER NOT NULL REFERENCES assets(asset_id),
    discovery_source  TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'Open'
        CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
    created_date      DATETIME NOT NULL DEFAULT (datetime('now')),
    resolution_date   DATETIME,
    updated_date      DATETIME NOT NULL DEFAULT (datetime('now')),
    CONSTRAINT uq_vulnerability_cve_asset UNIQUE (cve_id, asset_id)
);

CREATE INDEX idx_vulnerabilities_asset_id ON vulnerabilities(asset_id);

-- =====================================================================
-- Sample data (owners are the test accounts from 01_...sql)
-- =====================================================================

INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, operating_system, department, owner_id, location, criticality, status, created_date, updated_date) VALUES
(1, 'Payroll Database Server',    'Database',       '10.0.1.15',   'Ubuntu 22.04 LTS',       'Finance',         1, 'Beirut HQ, Server Room A', 'Critical', 'Active',            '2026-09-05 09:00:00', '2026-09-05 09:00:00'),
(2, 'HR Web Portal',              'Application',    '10.0.2.20',   'Windows Server 2022',    'Human Resources', 1, 'Beirut HQ, Server Room A', 'High',     'Active',            '2026-09-05 09:10:00', '2026-09-05 09:10:00'),
(3, 'Finance Laptop 07',          'Workstation',    '10.0.5.107',  'Windows 11 Pro',         'Finance',         3, 'Beirut HQ, Floor 3',       'Medium',   'Active',            '2026-09-06 10:00:00', '2026-09-06 10:00:00'),
(4, 'Core Firewall',              'Network Device', '10.0.0.1',    'FortiOS 7.4',            'IT Security',     1, 'Beirut HQ, Server Room A', 'Critical', 'Active',            '2026-09-06 10:30:00', '2026-09-06 10:30:00'),
(5, 'Mail Server',                'Server',         '10.0.1.25',   'Windows Server 2019',    'IT',              2, 'Beirut HQ, Server Room B', 'High',     'Under Maintenance', '2026-09-07 08:00:00', '2026-09-07 08:00:00'),
(6, 'Backup Storage Bucket',      'Cloud Resource', '172.16.10.5', NULL,                     'IT',              1, 'AWS eu-central-1',         'High',     'Active',            '2026-09-07 08:30:00', '2026-09-07 08:30:00'),
(7, 'Compliance Workstation 02',  'Workstation',    '10.0.5.112',  'Windows 11 Pro',         'Compliance',      4, 'Beirut HQ, Floor 2',       'Low',      'Active',            '2026-09-08 11:00:00', '2026-09-08 11:00:00'),
(8, 'Legacy File Server',         'Server',         '10.0.1.40',   'Windows Server 2012 R2', 'Operations',      1, 'Jounieh Branch',           'Medium',   'Inactive',          '2026-09-08 11:30:00', '2026-09-08 11:30:00');

INSERT INTO threats (threat_type, threat_value, description, severity, source, date_added, updated_date) VALUES
('IP Address',        '185.220.101.4',            'Tor exit node seen brute-forcing SSH on the perimeter firewall',                      'High',     'AbuseIPDB',              '2026-09-10 09:00:00', '2026-09-10 09:00:00'),
('IP Address',        '45.155.205.233',           'Command-and-control server linked to a ransomware campaign',                          'Critical', 'CISA advisory',          '2026-09-11 14:00:00', '2026-09-11 14:00:00'),
('IP Address',        '203.0.113.50',             'Repeated port scans against the DMZ',                                                 'Medium',   'Internal SOC',           '2026-09-12 16:20:00', '2026-09-12 16:20:00'),
('Domain',            'secure-paypa1-login.com',  'Phishing domain impersonating PayPal, used in payroll-themed emails',                 'High',     'PhishTank',              '2026-09-13 10:15:00', '2026-09-13 10:15:00'),
('Domain',            'update-microsoft-support.net', 'Fake software update site delivering a remote access tool',                       'Medium',   'Internal SOC',           '2026-09-14 13:40:00', '2026-09-14 13:40:00'),
('File Hash',         '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'SHA-256 of the EICAR antivirus test file, used to validate detection', 'Low', 'VirusTotal', '2026-09-15 09:30:00', '2026-09-15 09:30:00'),
('File Hash',         '44d88612fea8a8f36de82e1278abb02f', 'MD5 of the EICAR antivirus test file',                                         'Low',      'VirusTotal',             '2026-09-15 09:35:00', '2026-09-15 09:35:00'),
('Malware Signature', 'Emotet loader HTTP POST beacon pattern', 'Network pattern of Emotet loaders contacting their C2 servers',                 'High',     'Vendor threat feed',     '2026-09-16 12:00:00', '2026-09-16 12:00:00');

INSERT INTO vulnerabilities (title, description, cve_id, cvss_score, severity, asset_id, discovery_source, status, created_date, resolution_date, updated_date) VALUES
('Log4Shell remote code execution',  'Apache Log4j 2 JNDI lookup lets attackers run code through crafted log messages.', 'CVE-2021-44228', 10.0, 'Critical', 2, 'Nessus scan',        'Under Investigation', '2026-09-18 09:00:00', NULL,                  '2026-09-18 09:00:00'),
('OpenSSH regreSSHion',              'Race condition in the OpenSSH server signal handler allows remote code execution.', 'CVE-2024-6387',   8.1, 'High',     1, 'Nessus scan',        'Open',                '2026-09-18 09:05:00', NULL,                  '2026-09-18 09:05:00'),
('PrintNightmare',                   'Windows Print Spooler flaw allows remote code execution with SYSTEM rights.',        'CVE-2021-34527',  8.8, 'High',     8, 'Penetration test',   'In Progress',         '2026-09-19 10:00:00', NULL,                  '2026-09-19 10:00:00'),
('HTTP/2 Rapid Reset',               'Request cancellation abuse enables denial of service against HTTP/2 servers.',       'CVE-2023-44487',  7.5, 'High',     5, 'Vendor advisory',    'Resolved',            '2026-09-20 11:00:00', '2026-10-02 15:00:00', '2026-10-02 15:00:00'),
('Terrapin SSH prefix truncation',   'Attackers can drop SSH handshake messages and weaken connection security.',          'CVE-2023-48795',  5.9, 'Medium',   4, 'Configuration audit','Open',                '2026-09-21 14:00:00', NULL,                  '2026-09-21 14:00:00'),
('curl cookie injection',            'curl may load cookies from an unintended file in specific conditions.',              'CVE-2023-38546',  3.7, 'Low',      3, 'Endpoint agent',     'Closed',              '2026-09-22 08:30:00', '2026-09-25 10:00:00', '2026-09-25 10:00:00');
