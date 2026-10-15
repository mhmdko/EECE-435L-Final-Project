# Security Playbook and Response Automation Service
Owner: [Titia's full name]

Stores response playbooks per incident category and severity, each with ordered response actions.

- POST /playbooks (Admin)
- GET /playbooks (Admin, Analyst, Auditor)
- GET /playbooks/{id} (Admin, Analyst, Auditor)
- POST /playbooks/{id}/actions (Admin, Analyst)
- PUT /actions/{id}/status (Admin, Analyst)
- DELETE /playbooks/{id} (Admin)
