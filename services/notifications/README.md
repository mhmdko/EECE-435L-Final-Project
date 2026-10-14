# Notification and Alert Management Service
Owner: Mohammad Kourani

Sends users alerts about incident assignments, threats, vulnerabilities, and system events.

- POST /notifications (Admin)
- GET /notifications/user/{user_id} (all roles)
- GET /notifications/{id} (all roles)
- PUT /notifications/{id}/read (Admin, Analyst, Employee)
- GET /notifications/search (Admin, Analyst, Auditor)
- DELETE /notifications/{id} (Admin)
