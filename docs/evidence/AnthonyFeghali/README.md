# Evidence checklist: Anthony Feghali

Screenshots must come from our own running system. Save them in this folder, and use the caption format required by the course: **Anthony Feghali - API title - what it does**.

**Before you start:**
1. Run `python init_db.py`, then `python run.py`.
2. In Postman, run the requests in folder **0. Setup** first (they log in and store the tokens).
3. Then go through folders 1, 2, 3 in numeric order, top to bottom.

Each Postman screenshot must show the request name, method and URL, body (if any), and the response with its status code.

For database screenshots, open `instance/security.db` in DB Browser for SQLite with **Open Database Read Only**, and press F5 to refresh before each shot.

## Database

- [ ] `db-structure.png`: the **Database Structure** tab, with the assets, threats, and vulnerabilities tables expanded
- [ ] `db-schema-diagram.png`: `docs/database-schema.md` opened on GitHub, showing the drawn diagram

## Asset Management (folder 1)

- [ ] `assets-db-before.png`: the assets table before any request (8 sample rows)
- [ ] `assets-add-server.png`, `assets-add-workstation.png`, `assets-add-cloud.png`: three successful creations (201)
- [ ] `assets-db-after-add.png`: the assets table showing the three new rows
- [ ] `assets-add-invalid-ip.png`, `assets-add-invalid-type.png`, `assets-add-invalid-criticality.png`, `assets-add-invalid-status.png`, `assets-add-missing-fields.png` (400)
- [ ] `assets-add-owner-not-found.png` (404) and `assets-add-denied.png` (analyst, 403)
- [ ] `assets-update.png`: criticality and status change (200)
- [ ] `assets-update-db-after.png`: the same row in the database after the update
- [ ] `assets-update-owner.png`, `assets-update-invalid.png`, `assets-update-not-found.png`
- [ ] `assets-get-all.png` (admin), `assets-get-all-auditor.png`, `assets-get-all-denied.png` (analyst and employee, 403)
- [ ] `assets-get-one.png`: asset 1 with its vulnerabilities; `assets-get-invalid.png` (404)
- [ ] `assets-search-name.png`, `assets-search-type.png`, `assets-search-ip.png`, `assets-search-department.png`, `assets-search-criticality.png`, `assets-search-combined.png`, `assets-search-invalid.png`
- [ ] `assets-delete-denied.png` (analyst, 403), `assets-delete-linked.png` (409), `assets-delete-success.png` (200), `assets-delete-not-found.png` (404)

## Threat Intelligence (folder 2)

- [ ] `threats-add-ip.png`: shows `analysts_alerted`
- [ ] `threats-add-domain.png`, `threats-add-hash.png`, `threats-add-signature.png`
- [ ] `threats-db-records.png`: the threats table with the new rows
- [ ] `threats-alert-notification.png`: the notifications table showing the new **Threat Alert** rows
- [ ] `threats-duplicate.png` (409)
- [ ] `threats-invalid-ip.png`, `threats-invalid-domain.png`, `threats-invalid-hash.png`, `threats-invalid-severity.png` (400)
- [ ] `threats-add-denied.png` (403)
- [ ] `threats-get-all.png`, `threats-get-all-denied.png`
- [ ] `threats-get-one.png`, `threats-get-not-found.png`
- [ ] `threats-search-type.png`, `threats-search-value.png`, `threats-search-severity.png`, `threats-search-source.png`, `threats-search-combined.png`, `threats-search-denied.png`
- [ ] `threats-db-before-update.png`: the row before the update
- [ ] `threats-update.png`: the update request (200)
- [ ] `threats-db-after-update.png`: the same row after the update
- [ ] `threats-update-value-blocked.png`, `threats-update-invalid.png`, `threats-update-denied.png`
- [ ] `threats-delete-denied.png`, `threats-delete-success.png`, `threats-delete-not-found.png`

## Vulnerability Management (folder 3)

- [ ] `vulns-add-critical.png`: shows `owner_alerted`
- [ ] `vulns-add-medium.png`, `vulns-add-third.png`
- [ ] `vulns-db-records.png`: the vulnerabilities table with the new rows
- [ ] `vulns-duplicate.png` (409)
- [ ] `vulns-invalid-cve.png`, `vulns-invalid-cvss.png`, `vulns-severity-mismatch.png` (400)
- [ ] `vulns-asset-not-found.png` (404), `vulns-add-denied.png` (403)
- [ ] `vulns-get-all.png`, `vulns-get-all-denied.png`, `vulns-get-one.png`, `vulns-get-invalid.png`
- [ ] `vulns-db-before-update.png`: the new Critical row while still Open
- [ ] `vulns-status-1-investigation.png`, `vulns-status-skip-rejected.png`, `vulns-status-2-in-progress.png`, `vulns-status-3-resolved.png`
- [ ] `vulns-db-after-update.png`: the same row now Resolved, with a resolution_date
- [ ] `vulns-update-score.png`, `vulns-resolution-date-rejected.png`, `vulns-closed-rejected.png`, `vulns-update-denied.png`
- [ ] `vulns-search-cve.png`, `vulns-search-severity.png`, `vulns-search-asset-id.png`, `vulns-search-asset-name.png`, `vulns-search-status.png`, `vulns-search-combined.png`, `vulns-search-invalid.png`
- [ ] `vulns-delete-denied.png`, `vulns-delete-success.png`, `vulns-delete-not-found.png`

## Summary and GitHub

- [ ] `postman-run-summary.png`: Postman **Run collection** results showing every test passed (take this on a separate run, then rebuild the database with `python init_db.py` before the manual pass)
- [ ] `github-commits.png`: the commit history showing these commits from Anthony's account
