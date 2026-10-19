# Vulnerability Management Service

**Owner:** Anthony Feghali
**Code:** `models.py` (the `vulnerabilities` table), `routes.py` (6 endpoints)

Tracks security vulnerabilities found on assets, from discovery to closure, with CVE ids, CVSS scores, and severity.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/vulnerabilities` | Security Administrator | 201 |
| 2 | GET | `/vulnerabilities` | Security Administrator, Security Analyst, Auditor | 200 |
| 3 | GET | `/vulnerabilities/{id}` | Security Administrator, Security Analyst, Auditor | 200 |
| 4 | PUT | `/vulnerabilities/{id}` | Security Administrator, Security Analyst | 200 |
| 5 | GET | `/vulnerabilities/search` | Security Administrator, Security Analyst, Auditor | 200 |
| 6 | DELETE | `/vulnerabilities/{id}` | Security Administrator | 200 |

Regular Employees have no access to vulnerability management.

## Request bodies

**Create:** `title`, `description`, `cve_id`, `cvss_score`, `severity`, `asset_id`, `discovery_source` (all required). New vulnerabilities start as **Open**.

**Update:** at least one of `description`, `severity`, `status`, `cvss_score`, `resolution_date` (YYYY-MM-DD)

## Validation

| Field | Rule |
|-------|------|
| `cve_id` | Format `CVE-YYYY-NNNN` (stored in uppercase) |
| `cvss_score` | Number from 0.0 to 10.0 |
| `severity` | Low, Medium, High, or Critical, and it **must match the CVSS v3 band** of the score: Low 0.0 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0 |
| `asset_id` | Must be an existing asset; every vulnerability belongs to exactly one asset |
| Duplicates | The same CVE cannot be registered twice for the same asset (409) |
| `resolution_date` | Only once the status is Resolved or Closed; not before the record was created; not in the future |

**How severity is stored:** as text limited to the four allowed levels, enforced by the API and by a `CHECK` constraint in the database. The CVSS score is stored separately as a number, and the API keeps the two consistent.

## Status lifecycle

```
Open → Under Investigation → In Progress → Resolved → Closed
```

- **One step at a time:** status can only move to the next stage. Skipping a step, going backwards, or changing a Closed record is rejected with 400, and the message names the next allowed status.
- **Automatic resolution date:** moving to **Resolved** sets `resolution_date` to today, unless one is provided.
- **Next step shown:** `GET /vulnerabilities/{id}` includes `next_allowed_status`.

## Search filters

Combine any of these; every filter must match.

| Parameter | Example | Matching |
|-----------|---------|----------|
| `cve` | `?cve=2024` | contains |
| `severity` | `?severity=Critical` | exact |
| `asset_id` | `?asset_id=1` | exact |
| `asset` | `?asset=payroll` | asset name contains, any capitalization |
| `status` | `?status=Open` | exact |

## Connection to other services

- **Assets:** every vulnerability is linked to one asset, and `GET /assets/{id}` lists that asset's vulnerabilities.
- **Notifications:** when a **High** or **Critical** vulnerability is added, the affected asset's owner receives a **Vulnerability Alert** notification.
- **Audit log:** `VULNERABILITY_ADDED`, `VULNERABILITY_UPDATED` (with each change), and `VULNERABILITY_DELETED` are recorded automatically.
