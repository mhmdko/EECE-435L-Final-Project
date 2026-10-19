# Asset Management Service

**Owner:** Anthony Feghali
**Code:** `models.py` (the `assets` table), `routes.py` (6 endpoints)

Manages the organization's assets (servers, workstations, databases, applications, network devices, cloud resources) that incidents and vulnerabilities can affect.

## Endpoints

| # | Method | Endpoint | Who can call it | Success |
|---|--------|----------|-----------------|---------|
| 1 | POST | `/assets` | Security Administrator | 201 |
| 2 | PUT | `/assets/{id}` | Security Administrator | 200 |
| 3 | DELETE | `/assets/{id}` | Security Administrator | 200 |
| 4 | GET | `/assets` | Security Administrator, Auditor | 200 |
| 5 | GET | `/assets/{id}` | Security Administrator, Security Analyst, Auditor | 200 |
| 6 | GET | `/assets/search` | Security Administrator, Security Analyst, Auditor | 200 |

Regular Employees have no access to asset management.

## Request bodies

**Create**
- Required: `asset_name`, `asset_type`, `ip_address`, `department`, `owner_id`, `criticality`
- Optional: `operating_system`, `location`, `status` (defaults to Active)

**Update:** at least one of `asset_name`, `owner_id`, `department`, `criticality`, `status`, `ip_address`, `operating_system`, `location`

## Allowed values and validation

| Field | Rule |
|-------|------|
| `asset_type` | Server, Workstation, Database, Application, Network Device, Cloud Resource |
| `ip_address` | Valid IPv4 or IPv6 (checked with Python's `ipaddress` module) |
| `criticality` | Low, Medium, High, Critical |
| `status` | Active, Inactive, Under Maintenance |
| `owner_id` | Must be an existing user |
| `asset_name`, `department` | Required text, at most 100 characters |

**How criticality is stored:** as text limited to the four allowed levels. The API rejects anything else with a clear message, and a `CHECK` constraint in the database rejects it too, as a second safety net.

## Search filters

Combine any of these; every filter must match.

| Parameter | Example | Matching |
|-----------|---------|----------|
| `name` | `?name=server` | contains, any capitalization |
| `type` | `?type=Workstation` | exact |
| `ip` | `?ip=10.0.1.` | full IP, or its beginning (a subnet) |
| `department` | `?department=finance` | contains, any capitalization |
| `criticality` | `?criticality=Critical` | exact |
| `status` | `?status=Active` | exact |

## Relationships

| Related to | How |
|------------|-----|
| Owner | `owner_id` → `users.user_id`. A user who still owns assets cannot be deleted. |
| Department | stored as text on each asset |
| Vulnerabilities | `GET /assets/{id}` lists the vulnerabilities found on the asset |
| Incidents | linked from the Incidents service through the affected asset id |

## How deletion and authorization work

- **Who can delete:** only Security Administrators, enforced by `@roles_required(ADMIN)`. Any other role gets 403, and the attempt is recorded in the audit log as `UNAUTHORIZED_ACCESS`.
- **Linked assets are protected:** an asset that still has vulnerabilities or incidents linked to it cannot be deleted (409). The foreign keys pointing to it block the deletion, so nothing is left pointing to a missing asset.

## Audit events written automatically

`ASSET_CREATED`, `ASSET_UPDATED` (with each change as old → new), `ASSET_DELETED`
