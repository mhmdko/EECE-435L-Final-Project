# Database schema

Owner: Anthony Feghali

GitHub draws the diagram below automatically. For the report, open this file on GitHub and take a screenshot of the diagram.

Lines show foreign keys: `||--o{` means "one to many".

```mermaid
erDiagram
    users ||--o{ logs : "performs (SET NULL on delete)"
    users ||--o{ notifications : "receives (CASCADE on delete)"
    users ||--o{ assets : "owns"
    assets ||--o{ vulnerabilities : "has"

    users {
        INTEGER user_id PK
        TEXT full_name
        TEXT username UK "case-insensitive"
        TEXT email UK
        TEXT password_hash "salted scrypt"
        TEXT department
        TEXT role "4 allowed roles"
        TEXT account_status "Active, Inactive, Suspended"
        DATETIME created_date
        DATETIME last_login_date
    }

    logs {
        INTEGER log_id PK
        INTEGER user_id FK
        TEXT action
        TEXT description
        DATETIME timestamp
        TEXT severity "Information, Warning, Error, Critical"
        TEXT related_service
    }

    notifications {
        INTEGER notification_id PK
        INTEGER user_id FK
        TEXT title
        TEXT message
        TEXT notification_type
        TEXT severity "Low to Critical"
        TEXT status "Unread, Read"
        DATETIME creation_date
        DATETIME read_date
    }

    assets {
        INTEGER asset_id PK
        TEXT asset_name
        TEXT asset_type "6 allowed types"
        TEXT ip_address "IPv4 or IPv6"
        TEXT operating_system
        TEXT department
        INTEGER owner_id FK
        TEXT location
        TEXT criticality "Low to Critical"
        TEXT status "Active, Inactive, Under Maintenance"
        DATETIME created_date
        DATETIME updated_date
    }

    threats {
        INTEGER threat_id PK
        TEXT threat_type UK "unique with threat_value"
        TEXT threat_value UK
        TEXT description
        TEXT severity "Low to Critical"
        TEXT source
        DATETIME date_added
        DATETIME updated_date
    }

    vulnerabilities {
        INTEGER vulnerability_id PK
        TEXT title
        TEXT description
        TEXT cve_id UK "unique with asset_id"
        REAL cvss_score "0.0 to 10.0"
        TEXT severity "matches CVSS band"
        INTEGER asset_id FK
        TEXT discovery_source
        TEXT status "Open to Closed lifecycle"
        DATETIME created_date
        DATETIME resolution_date
        DATETIME updated_date
    }
```

**To be added by Titia Saikali:** `incidents` (linked to users as reporter and analyst, and to assets as the affected asset), `investigation_notes`, `playbooks`, and `response_actions`. Add them to the diagram above when `database/03_...sql` is ready.
