# Decommission checklist — Supabase + Railway

Written 2026-08-23, the day of the GCP cutover. **Do not start before 2026-09-06**
(two weeks of production traffic on Cloud Run with Supabase/Railway held as
rollback). Work top to bottom; each step assumes the ones above it are done.

Cloud Run service: `flow-dictation` (us-east1) · Cloud SQL: `flow-dictation-prod:us-east1:flow-dictation-db`, db `flowdictation`, user `fdapp`.

## 0. Preconditions (2026-09-06 or later)

- [ ] flowdictation.com has resolved to Cloud Run for ≥ 2 weeks with no rollback needed.
- [ ] Every item in the manual smoke checklist has been exercised on the live domain at least once
      (login, draft save, review, assist action, Quick Rad Question with references, Review-tab filters incl. Section).
- [ ] Confirm automated Cloud SQL backups are actually running (backups + PITR were enabled at creation):
      ```
      gcloud sql backups list --instance=flow-dictation-db --limit=10
      gcloud sql instances describe flow-dictation-db --format='value(settings.backupConfiguration.enabled,settings.backupConfiguration.pointInTimeRecoveryEnabled,settings.backupConfiguration.startTime)'
      ```
      Expect at least one `SUCCESSFUL` automated backup per day and `True True`.
- [ ] One last row-count comparison, Supabase vs Cloud SQL, to be sure nothing was written to Supabase after cutover
      (if anything did, migrate those rows by hand before continuing):
      ```
      # Supabase (Settings → Database → connection string)
      psql "$SUPABASE_URL_WITH_PASSWORD" -Atc "select 'reports', count(*) from reports union all select 'assist_messages', count(*) from assist_messages union all select 'shifts', count(*) from shifts"
      # Cloud SQL (with cloud-sql-proxy on :5433)
      PGPASSWORD=… psql -h 127.0.0.1 -p 5433 -U fdapp -d flowdictation -Atc "…same query…"
      ```

## 1. Railway

- [ ] In the Railway dashboard: open the flow-dictation service → Settings → **Remove service** (or delete the project).
      This stops the old app and its auto-deploys from GitHub pushes.
- [ ] Remove the `flowdictation.com` custom domain from Railway if it is still listed there.
- [ ] Check Railway billing shows no remaining resources for this project.

## 2. Supabase

- [ ] Take a final export for the archive (in case anything is ever questioned):
      ```
      pg_dump "$SUPABASE_URL_WITH_PASSWORD" --schema=public --no-owner --no-privileges > ~/fd_supabase_final_$(date +%Y%m%d).sql
      ```
      Store it somewhere encrypted (it contains report text), then delete the local copy.
- [ ] Supabase dashboard → project `stiibyjagsbiombklojn` → Settings → General → **Pause project** first.
      Leave it paused for a week; if nothing breaks, **Delete project**.
- [ ] If no other project needs it, downgrade the Supabase organization from Pro to Free
      (Organization → Billing → change plan). Check the other projects on the org before doing this.
- [ ] The Supabase DB password was pasted into a chat session on 2026-08-22 — rotating it is moot once the
      project is deleted; if you keep the project paused instead, reset it (Settings → Database → Reset password).

## 3. Rotate both Cloud SQL passwords

Both were generated and printed once in a chat session on 2026-08-22; rotate now that the migration is settled.

- [ ] Generate and set a new `postgres` (superuser) password, then store it in your password manager:
      ```
      NEWPG=$(openssl rand -base64 36 | tr -d '/+=' | cut -c1-32); echo "$NEWPG"
      gcloud sql users set-password postgres --instance=flow-dictation-db --password="$NEWPG"
      ```
- [ ] Rotate `fdapp` — the app reads it from Secret Manager, so update the secret **and** the DB user, then
      redeploy so the service picks up the new version (the service references `fd-db-password:latest`):
      ```
      NEWAPP=$(openssl rand -base64 36 | tr -d '/+=' | cut -c1-32); echo "$NEWAPP"
      printf '%s' "$NEWAPP" | gcloud secrets versions add fd-db-password --data-file=-
      gcloud sql users set-password fdapp --instance=flow-dictation-db --password="$NEWAPP"
      gcloud run services update flow-dictation --region=us-east1 --update-secrets=PGPASSWORD=fd-db-password:latest
      curl -s https://flowdictation.com/api/health   # expect "database":"configured" and a working login afterwards
      ```
      Do the secret version and the user password back to back — between them, new Cloud Run instances would fail to connect.
- [ ] Update `PGPASSWORD` in your local `.env` to the new `fdapp` value.
- [ ] Disable the old secret versions:
      ```
      gcloud secrets versions list fd-db-password
      gcloud secrets versions disable 1 --secret=fd-db-password
      ```

## 4. Local machine

- [ ] Remove stale keys from `~/Desktop/flow-dictation/.env`: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`,
      `ANTHROPIC_API_KEY` (and any other unused provider keys — `OPENAI_API_KEY`, `ASSEMBLYAI_API_KEY`, `AWS_*`
      were left in place by the migration; the app no longer reads any of them).
      Revoke `ANTHROPIC_API_KEY` in the Anthropic console and the Supabase service-role key goes away with the project.
- [ ] Stop the local cloud-sql-proxy if you are not doing local development:
      ```
      pkill -f 'cloud-sql-proxy flow-dictation-prod'
      ```
      (Restart it with `cloud-sql-proxy flow-dictation-prod:us-east1:flow-dictation-db --port 5433` when you need it.)
- [ ] Delete the migration dump **only after** step 0's backup check passed:
      ```
      gcloud sql backups list --instance=flow-dictation-db --limit=5   # confirm recent SUCCESSFUL backups
      rm ~/fd_dump.sql
      ```
      Also delete the archive copy from step 2 once it is stored somewhere encrypted.
- [ ] `supabase.sql`, `seed.sql`, `update-impression-style.sql` in the repo are now historical; either delete them
      or rename `supabase.sql` → `schema.sql` and strip the RLS lines so it documents the Cloud SQL schema.

## 5. Done when

- [ ] Railway shows no service, Supabase project is deleted (or paused with a rotated password), both Cloud SQL
      passwords rotated, local `.env` trimmed, no dump files left on disk, and `gcloud sql backups list` shows
      daily backups.
