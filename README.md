# Security Incident Detection and Response Management System (Backend)

EECE 435L Final Project, Sprint 1
Team: Mohammad Kourani, Anthony Feghali, [Titia's full name]

A REST API backend that helps a security team manage cybersecurity incidents from the first report to closure. It tracks the assets incidents affect, known threats, and vulnerabilities, sends notifications, guides responses with playbooks, produces reports, and keeps an audit log of every security-relevant action. Four roles (Security Administrator, Security Analyst, Regular Employee, Auditor) control who can do what.

There is no frontend: every feature is used and tested through Postman.

---

## Contents

1. [What Sprint 1 achieves](#1-what-sprint-1-achieves)
2. [Framework and tech stack](#2-framework-and-tech-stack)
3. [Repository map](#3-repository-map)
4. [Requirements](#4-requirements)
5. [Build and run (rebuild the workspace)](#5-build-and-run-rebuild-the-workspace)
6. [Architecture](#6-architecture)
7. [Database](#7-database)
8. [Authentication and roles](#8-authentication-and-roles)
9. [Errors and validation](#9-errors-and-validation)
10. [Testing with Postman](#10-testing-with-postman)
11. [Adding a service (guide for teammates)](#11-adding-a-service-guide-for-teammates)
12. [Progress](#12-progress)
13. [Contributions and credits](#13-contributions-and-credits)
14. [References and AI use](#14-references-and-ai-use)

---

## 1. What Sprint 1 achieves

Nine services, three per team member, each with six REST endpoints:

| # | Service | What it does | Owner | Status |
|---|---------|--------------|-------|--------|
| 1 | Users and Identity | Registration, login, profiles, roles, account status | Mohammad Kourani | Done |
| 5 | Security Audit Logging | Records logins, changes, and denied requests; logs cannot be edited | Mohammad Kourani | Done |
| 8 | Notifications | Alerts users about assignments, threats, and system events | Mohammad Kourani | Done |
| 2 | Assets | Servers, workstations, databases, and apps that incidents can affect | Anthony Feghali | In progress |
| 4 | Threat Intelligence | Known malicious IPs, domains, and file hashes | Anthony Feghali | In progress |
| 7 | Vulnerabilities | CVEs found on assets, tracked from Open to Closed | Anthony Feghali | In progress |
| 3 | Incidents | Report, assign, investigate, and close incidents | [Titia's full name] | In progress |
| 6 | Security Reports | Statistics gathered from the other services | [Titia's full name] | In progress |
| 9 | Playbooks and Response | Step-by-step response procedures with tracked actions | [Titia's full name] | In progress |

---

## 2. Framework and tech stack

| Part | Choice | Why |
|------|--------|-----|
| Language | Python 3.10 or newer | Taught in the course; readable |
| Web framework | Flask 3 | Small and simple; each service is a Flask Blueprint |
| Database | SQLite | A single file, no server to install, easy for anyone to rebuild |
| Database access | Flask-SQLAlchemy | Object-oriented models; parameterized queries prevent SQL injection |
| Login tokens | PyJWT (JSON Web Tokens) | Stateless authentication: the token proves who the user is |
| Password hashing | Werkzeug (salted scrypt) | Passwords are never stored in plain text |
| Settings and secrets | python-dotenv | Secrets live in `.env`, which is never committed |
| API testing | Postman | One collection per team member, with automated tests |

---

## 3. Repository map

```
EECE-435L-Final-Project/
├── README.md                 this file
├── requirements.txt          Python packages to install
├── .env.example              template for your private .env file (fake values only)
├── .gitignore                keeps secrets, the database file, and venv out of Git
├── run.py                    starts the API server
├── init_db.py                rebuilds the database from the SQL scripts
├── app/
│   ├── __init__.py           creates the app and loads every service automatically
│   ├── config.py             reads settings from .env
│   ├── extensions.py         shared database object
│   ├── common/               code shared by all services
│   │   ├── auth.py           login tokens and the @roles_required check
│   │   ├── errors.py         standard success and error responses
│   │   ├── validation.py     input checks (required fields, email, allowed values, ...)
│   │   └── time_utils.py     date and time helpers
│   └── services/             one folder per service
│       ├── users/            Mohammad Kourani
│       ├── logs/             Mohammad Kourani
│       ├── notifications/    Mohammad Kourani
│       ├── assets/           Anthony Feghali
│       ├── threats/          Anthony Feghali
│       ├── vulnerabilities/  Anthony Feghali
│       ├── incidents/        [Titia's full name]
│       ├── reports/          [Titia's full name]
│       └── playbooks/        [Titia's full name]
├── database/                 SQL scripts, run in name order by init_db.py
│   ├── 01_users_logs_notifications.sql        Mohammad Kourani
│   ├── 02_assets_threats_vulnerabilities.sql  Anthony Feghali
│   └── 03_incidents_playbooks.sql             [Titia's full name]
├── postman/                  one Postman collection per team member
└── docs/
    ├── architecture-diagram.png   [Titia's full name]
    ├── schema-diagram.png         Anthony Feghali
    └── evidence/                  screenshots from our running system, per member
```

Each service folder contains:

| File | Purpose |
|------|---------|
| `models.py` | The database table as a Python class, with every column explained |
| `routes.py` | The six endpoints, each with a comment naming its author and allowed roles |
| `service.py` | (optional) Functions other services can call |
| `README.md` | Endpoints, roles, rules, and fields for that service |

---

## 4. Requirements

- Python 3.10 or newer (`python --version`)
- Git
- Postman (desktop app)
- The Python packages in `requirements.txt` (installed in step 5)

---

## 5. Build and run (rebuild the workspace)

These steps rebuild the project on a new machine from nothing. Commands are for the Windows Command Prompt; on macOS or Linux, the differences are noted.

**1. Get the code**
```
git clone https://github.com/mhmdko/EECE-435L-Final-Project.git
cd EECE-435L-Final-Project
```

**2. Create a virtual environment and install the packages**
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
On macOS or Linux, activate with `source venv/bin/activate` instead.

**3. Create your private settings file**
```
copy .env.example .env
```
On macOS or Linux, use `cp .env.example .env`. Then open `.env` and replace both secret values with long random strings. Never commit `.env`.

**4. Build the database with sample data**
```
python init_db.py
```
This deletes any old database and runs every script in `database/`. Run it again any time you want to start over with clean data.

**5. Start the API**
```
python run.py
```
Open http://127.0.0.1:5000 in a browser. You should see the list of loaded services.

**6. Test with Postman**
Import the files in `postman/`, then run each collection from top to bottom (see section 10).

---

## 6. Architecture

<!-- Owner: [Titia's full name]. Add docs/architecture-diagram.png and describe how the services communicate. -->

_To be completed by [Titia's full name]._

How the shared parts work today:

- All services run inside one Flask application. Each service is a Blueprint in its own folder under `app/services/` and is registered automatically.
- Every protected request passes through `@roles_required`, which checks the login token, the account status, and the user's role before the service code runs.
- Services cooperate through shared functions: any service records audit events with `log_event()` and alerts users with `create_notification()`.

---

## 7. Database

<!-- Owner: Anthony Feghali. Add docs/schema-diagram.png, then describe every table, key, and relationship. -->

_Full schema description to be completed by Anthony Feghali._

Tables created by `database/01_users_logs_notifications.sql` (Mohammad Kourani):

| Table | Primary key | Foreign keys | Notes |
|-------|-------------|--------------|-------|
| users | user_id | none | username and email are unique (case-insensitive); role and account_status are limited to their allowed values |
| logs | log_id | user_id → users (SET NULL on delete) | a trigger blocks any UPDATE, so records cannot be edited; logs survive when their user is deleted |
| notifications | notification_id | user_id → users (CASCADE on delete) | type, severity, and status are limited to their allowed values |

Design decisions:
- **Allowed values are enforced in two places:** in the API (clear error messages) and with `CHECK` constraints in the database (a safety net).
- **Audit logs are protected at the database level:** even someone with direct database access cannot edit a log through normal SQL.
- **Deleting a user keeps their audit history** (user_id becomes empty) but removes their notifications, which are only meaningful to them.

### Test accounts (sample data)

| id | username | password | role | status |
|----|----------|----------|------|--------|
| 1 | admin | Admin@1234 | Security Administrator | Active |
| 2 | analyst | Analyst@1234 | Security Analyst | Active |
| 3 | employee | Employee@1234 | Regular Employee | Active |
| 4 | auditor | Auditor@1234 | Auditor | Active |
| 5 | suspended.user | Suspended@1234 | Regular Employee | Suspended |
| 6 | inactive.user | Inactive@1234 | Regular Employee | Inactive |

These exist only in the local sample database. They are not real credentials.

---

## 8. Authentication and roles

1. A user logs in with `POST /users/login`. The password is hashed and compared with the stored hash.
2. If it matches and the account is Active, the API returns a **token** (a JWT signed with `JWT_SECRET`, valid for 8 hours by default).
3. The client sends the token on every request: `Authorization: Bearer <token>`.
4. `@roles_required(...)` on each route then:
   - rejects a missing, invalid, or expired token with **401**
   - rejects an account that is no longer Active with **403**
   - rejects a role that is not allowed with **403**
   - records every rejection in the audit log as `UNAUTHORIZED_ACCESS`
5. Some routes add ownership rules. For example, an employee may only update their own profile.

| Role | In short |
|------|----------|
| Security Administrator | Manages everything |
| Security Analyst | Investigates incidents; reads threats, vulnerabilities, assets, and some logs |
| Regular Employee | Registers, manages own profile, reports incidents, reads own notifications |
| Auditor | Read-only access for oversight |

---

## 9. Errors and validation

Every response uses the same format:

```json
{ "status": "success", "message": "User registered successfully", "data": { } }
{ "status": "error",   "message": "User does not have permission to perform this operation" }
```

| Code | Meaning |
|------|---------|
| 400 | Invalid input: missing field, wrong format, value not allowed, unexpected field |
| 401 | Not logged in: missing, invalid, or expired token; wrong username or password |
| 403 | Logged in but not allowed: wrong role, inactive account, or someone else's data |
| 404 | The requested record or endpoint does not exist |
| 405 | Method not allowed (for example, trying to edit an audit log) |
| 409 | Conflict with existing data (for example, a duplicate username) |
| 500 | Unexpected server error (details go to the server console, never to the client) |

Validation rules are listed in each service's README. Protection against malicious input:
- Bodies must be JSON objects.
- Unexpected fields are rejected.
- Text is trimmed and length-limited.
- All database access uses parameterized queries, which blocks SQL injection.

---

## 10. Testing with Postman

1. Run `python init_db.py`, then `python run.py`.
2. In Postman, click **Import** and select the files in `postman/`.
3. Open a collection and click **Run**, keeping the default order.
   - The **Setup** folder logs in one account per role and saves the tokens automatically.
   - Every request has tests that check the expected status code.

| Collection | Owner | Requests |
|------------|-------|----------|
| `MohammadKourani.postman_collection.json` | Mohammad Kourani | 67 (all passing) |
| `AnthonyFeghali.postman_collection.json` | Anthony Feghali | to be added |
| `[Titia].postman_collection.json` | [Titia's full name] | to be added |

Request names follow the format **Full Name - API title - what it does**, which matches the screenshot caption format required by the course.

No real secrets are stored in the collections. Tokens are saved in collection variables only while Postman runs.

---

## 11. Adding a service (guide for teammates)

**1. Create your folder** `app/services/<service>/` with an empty `__init__.py`, plus `models.py`, `routes.py`, and `README.md`.

**2. In `routes.py`, create a Blueprint named `bp`.** The app finds and registers it automatically, so you don't need to edit `app/__init__.py`.

```python
from flask import Blueprint, g
from app.common.auth import roles_required, ADMIN, ANALYST, AUDITOR, EMPLOYEE
from app.common.errors import ApiError, success
from app.common.validation import get_json_body, require_choice, require_text
from app.extensions import db
from app.services.logs.service import log_event

bp = Blueprint("assets", __name__, url_prefix="/assets")

@bp.post("")
@roles_required(ADMIN)
def add_asset():
    """
    Author: Anthony Feghali
    Add a new asset. Who can call it: Security Administrator.
    """
    body = get_json_body(required=("asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality"))
    # ... validate, create the model, db.session.add(...), db.session.commit()
    log_event(g.current_user.user_id, "ASSET_CREATED", "Asset 'web-01' added", "Information", "Assets")
    return success("Asset created successfully", asset.to_dict(), 201)
```

**3. Shared tools you can use:**

| Tool | What it does |
|------|--------------|
| `@roles_required(ADMIN, ...)` | Login and role check; the current user is in `g.current_user` |
| `reject_forbidden(user, "message")` | For ownership rules; returns 403 and logs the attempt |
| `get_json_body(required=..., optional=...)` | Reads the JSON body; rejects missing or unexpected fields |
| `require_text`, `require_choice`, `require_int`, `require_email`, `require_date` | Validate single values |
| `raise ApiError("message", 404)` | Return any error in the standard format |
| `success("message", data, 201)` | Return a success response in the standard format |
| `log_event(user_id, action, description, severity, service)` | Write an audit record; use for every create, update, and delete |
| `create_notification(user_id, title, message, type, severity)` | Alert a user; for example, on incident assignment |

**4. Add your SQL script** in `database/` (`02_...sql` or `03_...sql`) with `CREATE TABLE` statements and sample data. Use these rules for foreign keys to `users(user_id)`:
- Use `ON DELETE SET NULL` for optional links, such as the analyst assigned to an incident.
- Use the default (no action) for required links, such as an asset's owner. The API then refuses to delete a user who still owns records and returns a clear 409 error.

**5. Export your Postman collection** to `postman/<YourName>.postman_collection.json`.

---

## 12. Progress

| Item | Status |
|------|--------|
| Project structure, settings, shared auth, errors, and validation | Done |
| Users and Identity service (6 endpoints) | Done |
| Security Audit Logging service (6 endpoints) | Done |
| Notifications service (6 endpoints) | Done |
| Database script 01 with sample data | Done |
| Postman collection for services 1, 5, 8 (67 requests, all passing) | Done |
| Assets, Threat Intelligence, Vulnerabilities | In progress (Anthony Feghali) |
| Incidents, Reports, Playbooks | In progress ([Titia's full name]) |
| Architecture and schema diagrams | In progress |
| Evidence screenshots | In progress (each member) |
| Final report | In progress |

---

## 13. Contributions and credits

| Member | Services | Shared work | Report sections |
|--------|----------|-------------|-----------------|
| Mohammad Kourani | Users and Identity, Security Audit Logging, Notifications | Project setup, configuration, authentication and role checks, error format, validation helpers, database build script, README | Title page, Table of Contents, Introduction, Authentication and Authorization |
| Anthony Feghali | Assets, Threat Intelligence, Vulnerabilities | Database schema diagram | Database Design, Error Handling and Validation |
| [Titia's full name] | Incidents, Security Reports, Playbooks and Response | Architecture diagram, evidence checklist | System Architecture, GitHub and Version Control, References |

Each member pushes their own work from their own GitHub account. See the commit history for details.

---

## 14. References and AI use

**Documentation used**
- Flask: https://flask.palletsprojects.com
- Flask-SQLAlchemy: https://flask-sqlalchemy.palletsprojects.com
- PyJWT: https://pyjwt.readthedocs.io
- Werkzeug security helpers: https://werkzeug.palletsprojects.com/en/latest/utils/#module-werkzeug.security
- SQLite foreign keys and triggers: https://www.sqlite.org/foreignkeys.html, https://www.sqlite.org/lang_createtrigger.html
- Postman collections: https://learning.postman.com

**AI use**

| Member | Tool | Where it was used | Purpose |
|--------|------|-------------------|---------|
| Mohammad Kourani | Claude (Anthropic) | Project structure, shared modules in `app/common/`, the Users, Audit Logging, and Notifications services, `database/01_...sql`, the Postman collection, and this README | Generate the initial implementation, which was then reviewed, run, and tested on our machines |
| Anthony Feghali | | | |
| [Titia's full name] | | | |
