# System architecture

Owner: Titia Saikali

GitHub draws the diagrams below automatically. For the report, open this file on GitHub and take a screenshot of each diagram.

## 1. How a request flows

Every request from Postman passes the same checks before it reaches a service.

```mermaid
flowchart TB
    client["Postman (test client)<br/>sends JSON with 'Authorization: Bearer token'"]
    auth["Authentication and role check<br/>(app/common/auth.py)<br/>token valid? account Active? role allowed?"]
    reject["401 / 403 error<br/>+ UNAUTHORIZED_ACCESS audit log"]
    service["Service route<br/>validates input, applies business rules"]
    db[("SQLite database<br/>instance/security.db")]
    response["JSON response<br/>{status, message, data}"]

    client --> auth
    auth -- "rejected" --> reject
    auth -- "allowed" --> service
    service --> db
    service --> response
```

## 2. The nine services and how they work together

Solid arrows are calls between services. Dashed arrows are reads only.

```mermaid
flowchart LR
    subgraph M["Mohammad Kourani"]
        users["Users and Identity"]
        logs["Audit Logging"]
        notifs["Notifications"]
    end
    subgraph A["Anthony Feghali"]
        assets["Assets"]
        threats["Threat Intelligence"]
        vulns["Vulnerabilities"]
    end
    subgraph T["Titia Saikali"]
        incidents["Incidents"]
        playbooks["Playbooks and Response"]
        reports["Security Reports"]
    end

    incidents -- "check affected asset" --> assets
    incidents -- "check analyst role" --> users
    incidents -- "assignment and High/Critical alerts" --> notifs
    incidents -. "recommended playbook" .-> playbooks
    threats -- "High/Critical threat alerts analysts" --> notifs
    vulns -- "check affected asset" --> assets
    vulns -- "alert asset owner" --> notifs
    playbooks -- "notify assigned user" --> notifs
    reports -. "statistics" .-> users
    reports -. "statistics" .-> assets
    reports -. "statistics" .-> incidents
    reports -. "statistics" .-> threats
    reports -. "statistics" .-> vulns
    reports -. "statistics" .-> logs
```

Every service also writes to **Audit Logging** through `log_event()` on each create, update, delete, and denied request. Those arrows are left out to keep the diagram readable.

## 3. Incident lifecycle

```mermaid
stateDiagram-v2
    [*] --> Open: employee or admin reports
    Open --> UnderInvestigation: analyst assigned and starts
    UnderInvestigation --> Mitigated: threat contained
    Mitigated --> Resolved: fixed (resolution date recorded, reporter notified)
    Resolved --> Closed: reviewed
    Closed --> [*]
```

Each step must follow the previous one; skipping or going backwards is rejected.

## Design choices

- **One Flask application, nine Blueprints:** each service lives in its own folder and is registered automatically. This keeps services independent (separate files, owners, and URL prefixes) without having to run nine servers.
- **Services cooperate through shared functions:** `log_event()` and `create_notification()` act as internal APIs, and each service checks the others' records (does the asset exist? is the user an analyst?) through their models.
- **One shared database:** with foreign keys and `CHECK` constraints, it keeps the data consistent across services.
- **A single security gate:** the same authentication and role check runs for every protected endpoint, so authorization rules cannot be forgotten in one service.
