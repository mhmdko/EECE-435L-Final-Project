# Security Playbook and Response Automation Service

**Owner:** Titia Saikali
**Code:** `models.py` (the `playbooks`, `response_actions`, and `action_history` tables), `routes.py` (6 endpoints)

Stores standard incident response procedures as ordered steps, and tracks who is doing each step and how far they've got.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/playbooks` | Security Administrator | 201 |
| 2 | GET | `/playbooks` | Security Administrator, Security Analyst, Auditor | 200 |
| 3 | GET | `/playbooks/{id}` | Security Administrator, Security Analyst, Auditor | 200 |
| 4 | POST | `/playbooks/{id}/actions` | Security Administrator, Security Analyst | 201 |
| 5 | PUT | `/actions/{id}/status` | Security Administrator; Security Analyst (actions assigned to them, or unassigned) | 200 |
| 6 | DELETE | `/playbooks/{id}` | Security Administrator | 200 |

Regular Employees have no access to playbooks.

## Request bodies

| Endpoint | Body |
|----------|------|
| Create playbook | `name`, `description`, `incident_category`, `severity` |
| Add action | `action_description`, `step_number` (required); `assigned_user_id` (optional) |
| Update action | at least one of `status`, `assigned_user_id`, `completion_date` (YYYY-MM-DD) |

`GET /playbooks` accepts optional `?category=` and `?severity=` filters.

## How playbooks are organized

- **One playbook per category and severity pair:** for example "Phishing Attack / High", enforced by a `UNIQUE` constraint. Every incident therefore has one clear standard procedure, and `GET /incidents/{id}` shows it as `recommended_playbook`.
- **Categories:** the same seven as incidents.
- **Steps:** each playbook is a list of numbered response actions, always returned in step order.

## Action ordering rules

- **Numbering:** steps start at 1, and each step number is used once per playbook (409 if reused).
- **No gaps:** a new step must be at most one more than the highest existing step. With steps 1 to 3, the next must be 4 (400 otherwise).
- **Order of work:** a step can only start (In Progress) once every earlier step is Completed.

## Action status workflow

```
Pending → In Progress → Completed
```

- **One step at a time:** skipping a status or changing a Completed action is rejected (400).
- **Auto-assignment:** starting an unassigned action assigns it to the person who started it.
- **Completion date:** **Completed** records `completion_date` (today, unless a date is given). A completion date is only allowed on Completed actions, and never in the future.
- **Who can be assigned:** only Active Security Analysts or Administrators. Analysts can only assign actions to themselves. The assigned user receives a notification.
- **History:** every status change is saved in `action_history` (old status, new status, who, when) and shown in `GET /playbooks/{id}`, so the execution history is preserved.

## Access control for deletion

Only Security Administrators can delete a playbook, enforced by `@roles_required(ADMIN)`. Other roles get 403, logged as `UNAUTHORIZED_ACCESS`. Deleting a playbook also deletes its actions and their history (`ON DELETE CASCADE`), and the deletion itself is recorded in the audit log.

## Audit events written automatically

`PLAYBOOK_CREATED`, `RESPONSE_ACTION_ADDED`, `RESPONSE_ACTION_UPDATED`, `PLAYBOOK_DELETED`
