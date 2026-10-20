# Evidence checklist: Titia Saikali

Screenshots must come from our own running system. Save them in this folder, and use the caption format required by the course: **Titia Saikali - API title - what it does**.

**Before you start:**
1. Run `python init_db.py`, then `python run.py`.
2. In Postman, run every request in folder **0. Setup** first. They log in one account per role and create a second analyst.
3. Then go through folders 1, 2, 3 in numeric order, top to bottom.

Each Postman screenshot must show the request name, method and URL, body (if any), and the response with its status code.

For database screenshots, open `instance/security.db` in DB Browser for SQLite with **Open Database Read Only**, and press F5 to refresh before each shot.

## Diagrams and database

- [ ] `architecture-request-flow.png`, `architecture-services.png`, `architecture-incident-lifecycle.png`: the three diagrams in `docs/architecture.md`, opened on GitHub
- [ ] `db-structure.png`: the **Database Structure** tab with incidents, investigation_notes, playbooks, response_actions, and action_history expanded

## Incident Management (folder 1)

- [ ] `incidents-db-before.png`: the incidents table before any request (7 sample rows)
- [ ] `incidents-create-critical.png`, `incidents-create-high.png`, `incidents-create-medium.png`, `incidents-create-low.png`: one per severity level
- [ ] `incidents-db-after-create.png`: the incidents table with the 4 new rows
- [ ] `incidents-admin-alert.png`: the notifications table showing the new **Security Alert** rows for the administrator
- [ ] `incidents-create-invalid-category.png`, `incidents-create-invalid-severity.png`, `incidents-create-missing-fields.png` (400)
- [ ] `incidents-create-asset-not-found.png` (404)
- [ ] `incidents-create-reporter-denied.png`, `incidents-create-analyst-denied.png`, `incidents-create-auditor-denied.png` (403)
- [ ] `incidents-get-all.png` (admin), `incidents-get-all-auditor.png`, `incidents-get-all-denied.png` (analyst and employee, 403)
- [ ] `incidents-get-own.png` (employee), `incidents-get-other-denied.png` (403), `incidents-get-invalid.png` (404)
- [ ] `incidents-get-with-notes.png`: incident 1 with notes and recommended playbook
- [ ] `incidents-start-before-assign.png` (400)
- [ ] `incidents-assign-denied.png`: analyst tries to assign (403)
- [ ] `incidents-assign-not-analyst.png` (400), `incidents-assign-user-not-found.png`, `incidents-assign-incident-not-found.png` (404)
- [ ] `incidents-assign-success.png` (200)
- [ ] `incidents-assign-db.png`: the incidents row now showing assigned_analyst_id = 2
- [ ] `incidents-assign-log.png`: the logs table showing the INCIDENT_ASSIGNED row
- [ ] `incidents-assign-notification.png`: the notifications table showing the analyst's **Incident Assignment** row
- [ ] `incidents-assign-resolved-rejected.png` (400)
- [ ] `incidents-status-denied.png`: unassigned analyst (403)
- [ ] `incidents-status-1-investigation.png`, `incidents-status-skip-rejected.png`, `incidents-status-2-mitigated.png`, `incidents-status-3-resolved.png`, `incidents-status-4-closed.png`
- [ ] `incidents-status-db-closed.png`: the incident row in the database, now Closed with a resolution_date
- [ ] `incidents-status-closed-final.png`, `incidents-status-invalid.png` (400)
- [ ] `incidents-note-1.png`, `incidents-note-2.png` (201)
- [ ] `incidents-notes-db.png`: the investigation_notes table showing the new notes linked by incident_id
- [ ] `incidents-note-empty.png` (400), `incidents-note-denied.png` (403), `incidents-note-closed.png` (400), `incidents-note-employee-denied.png` (403)
- [ ] `incidents-get-updated-notes.png`: incident 1 now showing all 4 notes

## Security Reports (folder 2)

- [ ] `reports-summary-admin.png`, `reports-summary-auditor.png`, `reports-summary-analyst-denied.png`, `reports-summary-employee-denied.png`
- [ ] `reports-incidents.png`, `reports-assets.png`, `reports-threats.png`, `reports-vulnerabilities.png`, `reports-activity.png`, `reports-activity-7-days.png`, `reports-activity-invalid.png`
- [ ] **Verification shots** (DB Browser, **Execute SQL** tab). Each shows the report numbers match the database:
  - [ ] `reports-verify-incidents.png`: `SELECT severity, COUNT(*) FROM incidents GROUP BY severity;`
  - [ ] `reports-verify-threats.png`: `SELECT severity, COUNT(*) FROM threats GROUP BY severity;`
  - [ ] `reports-verify-vulnerabilities.png`: `SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status;`
  - [ ] `reports-verify-activity.png`: `SELECT action, COUNT(*) FROM logs GROUP BY action ORDER BY 2 DESC;`

## Playbooks and Response (folder 3)

- [ ] `playbooks-create-1.png`, `playbooks-create-2.png` (201)
- [ ] `playbooks-db.png`: the playbooks table with the new rows
- [ ] `playbooks-create-duplicate.png` (409), `playbooks-create-invalid-category.png`, `playbooks-create-invalid-severity.png` (400), `playbooks-create-denied.png` (403)
- [ ] `actions-add-step-1.png`, `actions-add-step-2.png`, `actions-add-step-3.png` (201)
- [ ] `actions-db.png`: the response_actions table showing the three steps in order
- [ ] `actions-add-duplicate-step.png` (409), `actions-add-gap.png`, `actions-add-step-0.png`, `actions-add-employee.png` (400)
- [ ] `actions-add-assign-other-denied.png`, `actions-add-auditor-denied.png` (403), `actions-add-playbook-not-found.png` (404)
- [ ] `playbooks-get-all.png`, `playbooks-get-filter.png`, `playbooks-get-denied.png`
- [ ] `playbooks-get-one.png`: steps in order; `playbooks-get-invalid.png` (404)
- [ ] `actions-status-order-rejected.png`, `actions-status-skip-rejected.png` (400)
- [ ] `actions-status-step1-start.png`, `actions-status-step1-complete.png`, `actions-status-completed-final.png`
- [ ] `actions-status-other-analyst-denied.png` (403)
- [ ] `actions-status-step2-start.png`, `actions-status-step2-complete.png`
- [ ] `actions-status-future-date.png`, `actions-status-date-on-pending.png`, `actions-status-invalid.png` (400)
- [ ] `actions-status-auditor-denied.png` (403), `actions-status-not-found.png` (404)
- [ ] `playbooks-get-progress-history.png`: 2 of 3 completed, with history
- [ ] `actions-history-db.png`: the action_history table
- [ ] `playbooks-delete-denied.png` (403), `playbooks-delete-success.png` (200), `playbooks-delete-confirm.png` (404)

## Summary and GitHub

- [ ] `postman-run-summary.png`: Postman **Run collection** results showing every test passed (take this on a separate run, then rebuild the database with `python init_db.py` before the manual pass)
- [ ] `github-commits.png`: the commit history showing these commits from Titia's account
