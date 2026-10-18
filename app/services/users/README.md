# Users and Identity Management Service

**Owner:** Mohammad Kourani
**Code:** `models.py` (the `users` table), `routes.py` (6 endpoints)

Manages user accounts, login, roles, and account status.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/users/register` | Anyone (as Regular Employee); Security Administrator (any role) | 201 |
| 2 | POST | `/users/login` | Anyone with an Active account | 200 |
| 3 | PUT | `/users/{id}` | Security Administrator (any user); Regular Employee (own account) | 200 |
| 4 | DELETE | `/users/{id}` | Security Administrator | 200 |
| 5 | GET | `/users` | Security Administrator, Auditor | 200 |
| 6 | GET | `/users/{username}` | Security Administrator, Auditor; Regular Employee (own account) | 200 |

Security Analysts have no access to user management.

## Request bodies

**Register:** `full_name`, `username`, `email`, `password`, `department`, `role` (all required)

**Login:** `password` plus either `username` or `email`

**Update:** at least one of:
- `full_name`, `email`, `department`
- `role`, `account_status` (Security Administrator only)

## Rules and validation

| Field or case | Rule |
|---------------|------|
| `username` | 3 to 30 characters (letters, numbers, dots, underscores); unique, case-insensitive |
| `email` | Valid format; unique |
| `password` | At least 8 characters, with a letter, a number, and a symbol |
| `role` | `Security Administrator`, `Security Analyst`, `Regular Employee`, or `Auditor` |
| `account_status` | `Active`, `Inactive`, or `Suspended`; only Active users can log in |
| Self-registration | Without logging in, users can only register as Regular Employee |
| Self-protection | An administrator cannot delete, demote, or deactivate their own account |
| Deletion | A user who still owns other records (such as assets) cannot be deleted (409) |

## How duplicate usernames are handled

The API first checks whether the username exists (ignoring capital letters) and returns **409** with a clear message. The `UNIQUE COLLATE NOCASE` constraint on `users.username` is a second safety net: even if two requests arrive at the same moment, the database refuses the second one.

## Authentication mechanism

- **Storing passwords:** passwords are hashed with salted scrypt (Werkzeug) before storage, so the database never contains a plain password.
- **Logging in:** the given password is hashed the same way and compared with the stored hash.
- **Tokens:** on success the API returns a JWT signed with the server's secret key. It contains the user's id and role, and expires after 8 hours.
- **Protected requests:** each one sends `Authorization: Bearer <token>`. The `@roles_required` check (`app/common/auth.py`) verifies the token, the account status, and the role.

## Audit events written automatically

| Event | Logged as |
|-------|-----------|
| Successful login | `LOGIN_SUCCESS` |
| Failed or blocked login | `LOGIN_FAILED` |
| New account | `USER_CREATED` |
| Profile change | `USER_UPDATED` |
| Role change | `ROLE_CHANGED` |
| Status change | `ACCOUNT_STATUS_CHANGED` |
| Deletion | `USER_DELETED` |
| Every denied request | `UNAUTHORIZED_ACCESS` |
