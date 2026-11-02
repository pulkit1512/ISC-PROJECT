# SecureMed patient website

React + Vite frontend, FastAPI backend, SQLite through SQLAlchemy, and Alembic schema migrations. Existing CNN and ResNet18 checkpoints remain in `SecureMed_AI/`. The original dataset stays under `archive/` and is never bulk-imported into the website database.

## Run locally (PowerShell)

From `D:\SEM_5\ISC\ISC_PROJECT`:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Open http://127.0.0.1:8000. The launcher builds React if needed, then serves the built site and API together on one origin. No CORS setup is needed. For frontend changes, run `npm.cmd run build` inside `SecureMed_AI/website` and restart the server. Development can use `npm.cmd run dev` there, with FastAPI running on port 8000; Vite proxies `/api`.

## Website navigation

The public homepage introduces the project, models, and dataset. **Try it** and **Sign in** open login; **Create account** opens patient registration. Signed-in users enter their workspace. Click **My account** to open patient details, saved records, or sign out.

Profiles include optional symptoms, symptom duration, and relevant medical history. These fields are encrypted and included in saved profile snapshots; the image models do not use them as inputs. Existing profiles remain compatible.

## First use

1. Privately create the single admin account from PowerShell at the project root:

   ```powershell
   .\.venv\Scripts\python.exe -B SecureMed_AI\website\manage_admin.py
   ```

   Choose your username and password at the prompts (password input is hidden). There are no default credentials, public admin registration, or role selectors. Use the same website sign-in page as everyone else; the backend supplies the account role. Existing admin accounts are preserved and a second admin is rejected.
2. Choose **Create account** to register a patient (admin provisioning is not required for patient registration). Public signup can create only PATIENT accounts.
3. Sign in as the patient and complete fictional details.
4. Choose an image and model, then run prediction.
5. Optionally choose **Save encrypted record**. Unsaved predictions are held temporarily in encrypted server memory; no image or prediction row is inserted until explicit save.
6. Open **My records** to retrieve saved results and authenticated images.

Admin can activate/deactivate patient accounts and inspect safe audit/storage metadata. Admin cannot use patient endpoints to decrypt records. Deactivation revokes sessions. No doctor assignment or shared passphrase is required.

## Data and keys

`securemed_web.db` is separate from the old demonstration database, which is retained without alteration. Alembic applies schema revision `0001` on startup. The backend uses AES-256-GCM with fresh 96-bit nonces and record/field associated data. Argon2id hashes passwords. Browser sessions use expiring HttpOnly, SameSite=Strict cookies and CSRF tokens; session secrets are hashed in SQLite.

On Windows, `vault_key.dpapi` contains a key protected by Windows DPAPI for the current OS account. It is not a plaintext key and is separate from SQLite and browser assets. Preserve this file with a protected backup and the ability to use the original Windows account. Losing the encryption key makes encrypted records unrecoverable. On non-Windows systems, provide `SECUREMED_ENCRYPTION_KEY` as base64 encoding of 32 random bytes through a secret manager/environment. Never commit keys or databases.

Uploads are validated by file contents, dimensions, and size (default 10 MB, configurable using `SECUREMED_MAX_UPLOAD_MB`, 1–100). Original image bytes are not recompressed. Same-patient duplicates share an encrypted BLOB; each prediction remains an immutable separate record. A keyed SHA-256 lookup avoids exposing raw image fingerprints. Patient profiles use expected-version checks to reject conflicting edits. Patient details at prediction time are encrypted with the saved result.

## Verification

```powershell
.\.venv\Scripts\python.exe -B SecureMed_AI\website\test_api.py
```

Tests run on a disposable SQLite database with generated secrets and exercise both actual model checkpoints. `npm.cmd run build` validates the React production bundle.

## Scope and limitations

This is a local educational demonstration, not a clinical system or regulatory-compliant deployment. Use fictional identities and public de-identified images only. Model scores are not calibrated probabilities. Administrators of the host OS can access application memory; encrypted fields do not conceal all database metadata or ensure availability. Audit records are not tamper-proof against filesystem operators.

Run one backend worker: unsaved prediction drafts are process-local and expire after ten minutes (purged during subsequent prediction activity or logout). Restarting discards drafts, but saved records persist. The frontend makes clear when saving succeeds. Remote deployment requires HTTPS, secure cookies (`SECUREMED_HTTPS=1`), an explicitly configured origin and trusted host, managed secrets, backups, stronger abuse controls, and security review. Do not expose this default local configuration publicly.

For growth, migrate SQLite to PostgreSQL and encrypted BLOBs to separately encrypted object/file storage. Retain ownership checks, authenticated image references, protected keys and atomic migration verification. Neither migration is needed for this demonstration.
