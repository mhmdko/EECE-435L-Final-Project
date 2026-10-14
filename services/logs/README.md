# Security Audit Logging Service
Owner: Mohammad Kourani

Records logins, failed logins, data changes, role changes, and unauthorized access attempts. Logs are never edited after creation.

- POST /logs (Admin)
- GET /logs (Admin, Auditor)
- GET /logs/{id} (Admin, Analyst, Auditor)
- GET /logs/search (Admin, Analyst, Auditor)
- GET /logs/user/{user_id} (Admin, Auditor)
- DELETE /logs/{id} (Admin)
