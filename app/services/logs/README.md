# Security Audit Logging Service

**Owner:** Mohammad Kourani
**Code:** `models.py` (the `logs` table), `service.py` (the `log_event()` function), `routes.py` (6 endpoints)

Records security-relevant activity so administrators and auditors can review who did what, and when.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/logs` | Security Administrator | 201 |
| 2 | GET | `/logs` | Security Administrator, Auditor | 200 |
| 3 | GET | `/logs/{id}` | Security Administrator, Auditor, Security Analyst | 200 |
| 4 | GET | `/logs/search` | Security Administrator, Auditor, Security Analyst | 200 |
| 5 | DELETE | `/logs/{id}` | Security Administrator | 200 |
| 6 | GET | `/logs/user/{user_id}` | Security Administrator, Auditor | 200 |

Regular Employees have no access to audit logs.

## Search filters

Combine any of these; every filter must match.

| Parameter | Example | Matching |
|-----------|---------|----------|
| `user_id` | `?user_id=1` | exact |
| `date` | `?date=2026-10-01` | one whole day (YYYY-MM-DD) |
| `action` | `?action=login` | contains the text, any capitalization |
| `severity` | `?severity=Warning` | Information, Warning, Error, Critical |
| `service` | `?service=Users` | exact, any capitalization |

## Which events create logs

Most logs are written automatically by `log_event()`:

| Service | Events |
|---------|--------|
| Users | Successful and failed logins, user creation and deletion, profile updates, role changes, account status changes |
| Every service | Every rejected request (no token, bad token, inactive account, wrong role, someone else's data), logged as `UNAUTHORIZED_ACCESS` |
| Logs | Deleting a log (`LOG_DELETED`, severity Critical) |
| Notifications | Creating or deleting a notification |
| Other services | Their create, update, and delete operations, once implemented by each owner |

`POST /logs` lets an administrator add a record by hand.

## How logs are protected

- **No editing through the API:** there is no update endpoint. A `PUT` request returns 405.
- **No editing in the database:** a trigger (`logs_block_updates`) blocks any `UPDATE` on the table, so records cannot be changed even with direct SQL.
- **Deleting is restricted:** only Security Administrators can delete logs, and each deletion is itself logged as Critical.
- **Logs outlive their user:** if a user is deleted, their logs are kept and `user_id` becomes empty.

## How "logs by user" filtering works

`GET /logs/user/{user_id}` first checks that the user exists (404 if not), then returns every log whose `user_id` matches, newest first. A user with no activity gets an empty list and a clear message, not an error.
