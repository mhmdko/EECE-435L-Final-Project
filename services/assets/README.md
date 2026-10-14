# Asset Management Service
Owner: Anthony Feghali

Tracks organizational assets (servers, workstations, databases, applications) with owner, criticality, and status.

- POST /assets (Admin)
- PUT /assets/{id} (Admin)
- DELETE /assets/{id} (Admin)
- GET /assets (Admin, Auditor)
- GET /assets/{id} (Admin, Analyst, Auditor)
- GET /assets/search (Admin, Analyst, Auditor)
