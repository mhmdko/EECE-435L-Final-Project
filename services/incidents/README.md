# Incident Management Service
Owner: [Titia's full name]

Manages incidents through Open, Under Investigation, Mitigated, Resolved, and Closed. Invalid status jumps are rejected.

- POST /incidents (Admin, Employee)
- GET /incidents (Admin, Auditor)
- GET /incidents/{id} (Admin, Analyst, Employee, Auditor)
- PUT /incidents/{id}/assign (Admin)
- PUT /incidents/{id}/status (Admin, Analyst)
- POST /incidents/{id}/notes (Admin, Analyst)
