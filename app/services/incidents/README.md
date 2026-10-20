# Incident Management Service

**Owner:** Titia Saikali
**Code:** `models.py` (the `incidents` and `investigation_notes` tables), `routes.py` (6 endpoints)

Manages cybersecurity incidents through their whole lifecycle: reporting, assignment to an analyst, investigation notes, and closure.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/incidents` | Security Administrator, Regular Employee | 201 |
| 2 | GET | `/incidents` | Security Administrator, Auditor | 200 |
| 3 | GET | `/incidents/{id}` | Administrator, Analyst, Auditor; Regular Employee (own reports only) | 200 |
| 4 | PUT | `/incidents/{id}/assign` | Security Administrator | 200 |
| 5 | PUT | `/incidents/{id}/status` | Security Administrator; Security Analyst (incidents assigned to them) | 200 |
| 6 | POST | `/incidents/{id}/notes` | Security Administrator; Security Analyst (incidents assigned to them) | 201 |

## Request bodies

| Endpoint | Body |
|----------|------|
| Create | `title`, `description`, `category`, `severity`, `affected_asset_id` (required). `reporter_id` is optional and administrators only; by default the reporter is the logged-in user. |
| Assign | `analyst_id` |
| Status | `status` |
| Notes | `note_content` |

## Allowed values

| Field | Values |
|-------|--------|
| `category` | Malware Infection, Unauthorized Access, Phishing Attack, Data Leakage, Account Compromise, Denial of Service, Other |
| `severity` | Low (minor, limited impact), Medium (needs investigation), High (affects important systems or users), Critical (needs immediate response) |
| `status` | Open, Under Investigation, Mitigated, Resolved, Closed |

## Lifecycle (workflow)

```
Open → Under Investigation → Mitigated → Resolved → Closed
```

- **One step at a time:** skipping a step, going backwards, or changing a Closed incident is rejected (400). The message names the next allowed status.
- **Assignment first:** an analyst must be assigned before the investigation can start.
- **Resolving:** moving to **Resolved** records the resolution date and notifies the reporter.
- **Ownership:** analysts can only update incidents assigned to them; administrators can update any.

## Assignment validation

`PUT /incidents/{id}/assign` checks that:
1. the incident exists, and is not Resolved or Closed;
2. the user exists, is Active, and has the **Security Analyst** role (anyone else gets 400);
3. the caller is a Security Administrator (anyone else gets 403, logged as `UNAUTHORIZED_ACCESS`).

On success, the assignment is recorded in the audit log (`INCIDENT_ASSIGNED`), and the analyst receives an **Incident Assignment** notification.

## Investigation notes

- **One note, one incident:** each note belongs to exactly one incident, through `investigation_notes.incident_id` (foreign key), and records the analyst who wrote it and when.
- **Reading notes:** `GET /incidents/{id}` returns every note, oldest first.
- **No notes after closing:** notes cannot be added to a Closed incident.

## Connections to other services

| Service | How it is used |
|---------|----------------|
| Users | Reporter and analyst are users; assignment checks the role |
| Assets | `affected_asset_id` must exist. An asset with incidents cannot be deleted. |
| Notifications | High and Critical incidents send every administrator a **Security Alert**; assignment notifies the analyst; resolution notifies the reporter |
| Audit Logging | `INCIDENT_CREATED`, `INCIDENT_ASSIGNED`, `INCIDENT_STATUS_CHANGED`, `INVESTIGATION_NOTE_ADDED` |
| Playbooks | `GET /incidents/{id}` includes `recommended_playbook`, the playbook for the same category and severity |
