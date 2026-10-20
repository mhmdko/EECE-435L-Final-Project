# Security Reports Service

**Owner:** Titia Saikali
**Code:** `routes.py` (6 endpoints). This service has no table of its own.

Generates security statistics for administrators and auditors from the live data of every other service.

## Endpoints

| # | Method | Endpoint | Contents |
|---|--------|----------|----------|
| 1 | GET | `/reports/summary` | Users, active users, assets, critical assets, incidents, open incidents, critical open incidents, unassigned incidents, threats, critical threats, open vulnerabilities, playbooks, security events in the last 24 hours |
| 2 | GET | `/reports/incidents` | Total; by severity, status, and category; unassigned open incidents; 5 most recent |
| 3 | GET | `/reports/assets` | Total; critical assets; by type, criticality, and status; each critical asset with its open incidents and vulnerabilities |
| 4 | GET | `/reports/threats` | Total; by severity and type; 5 most recently added |
| 5 | GET | `/reports/vulnerabilities` | Total; by severity and status; average CVSS score; every Critical vulnerability |
| 6 | GET | `/reports/activity` | Total activities, login attempts, successful and failed logins, unauthorized attempts, by severity, 5 most performed actions, 5 most active users. Optional `?days=N` (1 to 365). |

**Who can call it:** Security Administrator and Auditor. Security Analysts and Regular Employees get 403, and the attempt is logged.

Every report also includes `generated_at` and `generated_by`, and is recorded in the audit log as `REPORT_GENERATED`.

## How the data is collected

| Report | Reads from |
|--------|------------|
| Summary | `users`, `assets`, `incidents`, `threats`, `vulnerabilities`, `playbooks`, `logs` |
| Incidents | `incidents` |
| Assets | `assets`, plus `incidents` and `vulnerabilities` for critical assets |
| Threats | `threats` |
| Vulnerabilities | `vulnerabilities`, plus `assets` for names |
| Activity | `logs`, plus `users` for usernames |

- **Using other services' models:** the report imports each service's model (for example `Incident` from the Incident Management Service) and counts rows with SQL `COUNT` and `GROUP BY` queries.
- **Always current:** the numbers are calculated at request time, so they match the database at that moment.
- **Every category listed:** each value appears even when its count is 0, so reports are easy to compare.

## Checking a report against the database

Example, for the threat report:
1. Run `GET /reports/threats` and note `by_severity.High`.
2. In DB Browser for SQLite, go to **Execute SQL** and run:
   ```sql
   SELECT severity, COUNT(*) FROM threats GROUP BY severity;
   ```
3. The numbers match.

The activity report can be checked the same way:
```sql
SELECT action, COUNT(*) FROM logs GROUP BY action ORDER BY 2 DESC;
```

**Note on timing:** the `REPORT_GENERATED` log for a request is written after the counts are calculated. Running the activity report twice in a row therefore shows one extra activity the second time.
