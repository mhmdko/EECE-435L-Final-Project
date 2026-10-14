# Users and Identity Service
Owner: Mohammad Kourani

Manages user accounts, login, roles, and account status (Active, Inactive, Suspended).

- POST /users/register (Admin, Employee)
- POST /users/login (any active user)
- PUT /users/{id} (Admin; Employee for own account)
- DELETE /users/{id} (Admin)
- GET /users (Admin, Auditor)
- GET /users/{username} (Admin, Auditor; Employee for own account)
