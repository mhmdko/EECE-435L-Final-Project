# Threat Intelligence Service
Owner: Anthony Feghali

Stores known threat indicators (IP addresses, domains, file hashes, malware signatures). The same type and value pair cannot be stored twice.

- POST /threats (Admin)
- GET /threats (Admin, Analyst, Auditor)
- GET /threats/{id} (Admin, Analyst, Auditor)
- GET /threats/search (Admin, Analyst)
- PUT /threats/{id} (Admin)
- DELETE /threats/{id} (Admin)
