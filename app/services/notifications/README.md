# Notification and Alert Management Service

**Owner:** Mohammad Kourani
**Code:** `models.py` (the `notifications` table), `service.py` (the `create_notification()` function), `routes.py` (6 endpoints)

Delivers security alerts and system messages to users and tracks whether they were read.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/notifications` | Security Administrator | 201 |
| 2 | GET | `/notifications/user/{user_id}` | All roles (Analyst and Employee: own only) | 200 |
| 3 | GET | `/notifications/{id}` | All roles (Analyst and Employee: own only) | 200 |
| 4 | PUT | `/notifications/{id}/read` | Security Administrator; Analyst and Employee (own only) | 200 |
| 5 | GET | `/notifications/search` | Security Administrator, Auditor; Analyst (own only) | 200 |
| 6 | DELETE | `/notifications/{id}` | Security Administrator | 200 |

## Request body (create)

`user_id`, `title`, `message`, `notification_type`, `severity` (all required)

## Allowed values

| Field | Values |
|-------|--------|
| `notification_type` | Incident Assignment, Security Alert, System Notification, Threat Alert, Vulnerability Alert |
| `severity` | Low, Medium, High, Critical |
| `status` | Unread, Read |

## Search filters

`user_id`, `type`, `severity`, `status`. Combine any of them, for example `?type=Security%20Alert&status=Unread`. Analysts' searches are automatically limited to their own notifications.

## When notifications are generated

- **By an administrator:** manually, with `POST /notifications`.
- **By other services:** automatically, through `create_notification()`. For example, when an incident is assigned (Incidents service), the analyst gets an Incident Assignment notification. Threat and vulnerability alerts work the same way.

## Status handling

- **On creation:** every notification starts as **Unread**, with an empty `read_date`.
- **Marking as read:** `PUT /notifications/{id}/read` sets the status to **Read** and records `read_date`.
- **Marking again:** returns 200 and keeps the original `read_date`.

## Permission validation

Analysts and Employees can only read or update notifications whose `user_id` is their own. Any other attempt returns 403 and is recorded in the audit log. Deleting a user also deletes their notifications.
