# Evidence checklist: Mohammad Kourani

Screenshots must come from our own running system. Save them in this folder, and use the caption format required by the course: **Mohammad Kourani - API title - what it does**.

**Before taking screenshots:** run `python init_db.py`, start `python run.py`, and run the Setup folder in Postman.

For database screenshots, open `instance/security.db` in DB Browser for SQLite (free).

## Database

- [ ] `db-structure.png`: the users, logs, and notifications tables (Database Structure tab)
- [ ] `db-users.png`: rows of the users table, showing hashed passwords

## Users and Identity

- [ ] `register-success.png`: Postman request and 201 response
- [ ] `register-db-record.png`: the new user row in the database
- [ ] `register-duplicate.png`: duplicate username, 409
- [ ] `login-success.png`: 200 with token
- [ ] `login-failed.png`: wrong password, 401
- [ ] `login-suspended.png`: suspended account, 403
- [ ] `update-user.png`: request and response
- [ ] `update-user-db.png`: the updated row in the database
- [ ] `delete-user-success.png`: admin deletes a user, 200
- [ ] `delete-user-denied.png`: analyst denied, 403
- [ ] `get-all-users.png`: list of users
- [ ] `get-user-found.png`: existing username
- [ ] `get-user-not-found.png`: missing username, 404

## Authentication and authorization

- [ ] `auth-insufficient.png`: employee calls GET /users, 403
- [ ] `auth-correct.png`: admin calls GET /users, 200
- [ ] `auth-no-token.png`: no token, 401

## Security Audit Logging

- [ ] `logs-create.png`: POST /logs, 201
- [ ] `logs-db-records.png`: rows in the logs table after running the collection
- [ ] `logs-get-all.png`: GET /logs
- [ ] `logs-get-one.png`: existing log
- [ ] `logs-get-invalid.png`: invalid id, 404
- [ ] `logs-search-action.png`, `logs-search-severity.png`, `logs-search-date.png`, `logs-search-combined.png`
- [ ] `logs-delete-success.png`: admin, 200
- [ ] `logs-delete-denied.png`: analyst, 403
- [ ] `logs-by-user.png`: user 1
- [ ] `logs-by-user-empty.png`: user 6, empty list
- [ ] `logs-cannot-modify.png`: PUT /logs/1, 405

## Notifications

- [ ] `notif-create.png`: 201
- [ ] `notif-db-records.png`: rows in the notifications table
- [ ] `notif-user-list.png`: employee's own notifications
- [ ] `notif-user-empty.png`: user 6, empty list
- [ ] `notif-get-one.png` and `notif-get-invalid.png`
- [ ] `notif-mark-read.png`: response
- [ ] `notif-mark-read-db.png`: database row before and after (status and read_date)
- [ ] `notif-search-status.png`, `notif-search-type.png`
- [ ] `notif-delete-success.png` and `notif-delete-denied.png`

## Validation (for the Error Handling section)

- [ ] `validation-invalid-email.png`
- [ ] `validation-weak-password.png`
- [ ] `validation-missing-fields.png`
- [ ] `validation-invalid-severity.png`

## GitHub

- [ ] `github-commits.png`: commit history showing these commits from my account
