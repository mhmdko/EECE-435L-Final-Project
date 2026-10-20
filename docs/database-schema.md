# Database schema

Owner: Anthony Feghali (incident and playbook tables: Titia Saikali)

GitHub draws the diagram below automatically. For the report, open this file on GitHub and take a screenshot of the diagram.

Lines show foreign keys: `||--o{` means "one to many".

```mermaid
erDiagram
    users ||--o{ logs : "performs (SET NULL on delete)"
    users ||--o{ notifications : "receives (CASCADE on delete)"
    users ||--o{ assets : "owns"
    assets ||--o{ vulnerabilities : "has"
    users ||--o{ incidents : "reports"
    users ||--o{ incidents : "is assigned (SET NULL on delete)"
    assets ||--o{ incidents : "is affected by"
    incidents ||--o{ investigation_notes : "contains (CASCADE)"
    users ||--o{ investigation_notes : "writes"
    users ||--o{ playbooks : "creates"
    playbooks ||--o{ response_actions : "contains (CASCADE)"
    users ||--o{ response_actions : "is assigned (SET NULL on delete)"
    response_actions ||--o{ action_history : "records (CASCADE)"

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

    incidents {
        INTEGER incident_id PK
        TEXT title
        TEXT description
        TEXT category "7 allowed categories"
        TEXT severity "Low to Critical"
        INTEGER reporter_id FK
        INTEGER affected_asset_id FK
        INTEGER assigned_analyst_id FK
        TEXT status "Open to Closed lifecycle"
        DATETIME created_date
        DATETIME resolution_date
        DATETIME updated_date
    }

    investigation_notes {
        INTEGER note_id PK
        INTEGER incident_id FK
        INTEGER analyst_id FK
        TEXT note_content
        DATETIME created_timestamp
    }

    playbooks {
        INTEGER playbook_id PK
        TEXT name
        TEXT description
        TEXT incident_category UK "unique with severity"
        TEXT severity UK
        INTEGER created_by FK
        DATETIME created_date
    }

    response_actions {
        INTEGER action_id PK
        INTEGER playbook_id FK
        TEXT action_description
        INTEGER step_number "unique per playbook"
        TEXT status "Pending, In Progress, Completed"
        INTEGER assigned_user_id FK
        DATETIME completion_date
        DATETIME created_date
        DATETIME updated_date
    }

    action_history {
        INTEGER history_id PK
        INTEGER action_id FK
        TEXT old_status
        TEXT new_status
        INTEGER changed_by FK
        DATETIME changed_at
    }
```

The incidents, investigation_notes, playbooks, response_actions, and action_history tables were added by Titia Saikali (`database/03_incidents_playbooks.sql`).
