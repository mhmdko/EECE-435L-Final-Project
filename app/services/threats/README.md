# Threat Intelligence Service

**Owner:** Anthony Feghali
**Code:** `models.py` (the `threats` table), `routes.py` (6 endpoints)

Maintains a database of known threat indicators (malicious IPs, suspicious domains, malware hashes, attack signatures) used during incident investigation.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/threats` | Security Administrator | 201 |
| 2 | GET | `/threats` | Security Administrator, Security Analyst, Auditor | 200 |
| 3 | GET | `/threats/{id}` | Security Administrator, Security Analyst, Auditor | 200 |
| 4 | GET | `/threats/search` | Security Administrator, Security Analyst | 200 |
| 5 | PUT | `/threats/{id}` | Security Administrator | 200 |
| 6 | DELETE | `/threats/{id}` | Security Administrator | 200 |

Regular Employees have no access to threat intelligence.

## Request bodies

**Create:** `threat_type`, `threat_value`, `description`, `severity`, `source` (all required)

**Update:** at least one of `description`, `severity`, `source`. The type and value identify the indicator, so they cannot be changed: delete the threat and add a new one instead.

## Validation by threat type

| Type | Value must be | Stored as |
|------|---------------|-----------|
| IP Address | Valid IPv4 or IPv6 | Standard form |
| Domain | Valid domain name, e.g. `evil-site.com` | Lowercase |
| File Hash | 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters | Lowercase; the response also reports the algorithm |
| Malware Signature | Any text up to 255 characters | As given |
| Other | Any text up to 255 characters | As given |

Severity must be Low, Medium, High, or Critical.

## How duplicates are prevented

- **Normalized first:** values are cleaned before comparison, so `EVIL.com` and `evil.com` count as the same domain.
- **Checked by the API:** it looks for an existing threat with the same type and value, and returns 409 with that threat's id.
- **Blocked by the database:** a `UNIQUE (threat_type, threat_value)` constraint catches anything the API check misses.

## Search filters

Combine any of these; every filter must match.

| Parameter | Example | Matching |
|-----------|---------|----------|
| `type` | `?type=IP%20Address` | exact |
| `value` | `?value=185.220` | contains, any capitalization |
| `severity` | `?severity=High` | exact |
| `source` | `?source=virustotal` | contains, any capitalization |

## Connection to other services

- **Notifications:** when a **High** or **Critical** threat is added, every active Security Analyst receives a **Threat Alert** notification. The response says how many analysts were alerted.
- **Audit log:** `THREAT_ADDED`, `THREAT_UPDATED`, and `THREAT_DELETED` are recorded automatically.
