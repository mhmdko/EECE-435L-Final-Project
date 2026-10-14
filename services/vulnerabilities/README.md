# Vulnerability Management Service
Owner: Anthony Feghali

Tracks vulnerabilities (CVEs) found on assets, with severity, CVSS score, and status from Open to Closed.

- POST /vulnerabilities (Admin)
- GET /vulnerabilities (Admin, Analyst, Auditor)
- GET /vulnerabilities/{id} (Admin, Analyst, Auditor)
- PUT /vulnerabilities/{id} (Admin, Analyst)
- GET /vulnerabilities/search (Admin, Analyst, Auditor)
- DELETE /vulnerabilities/{id} (Admin)
