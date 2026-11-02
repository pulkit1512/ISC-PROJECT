# Deploy SecureMed on Render

This configuration serves React, FastAPI, and both CPU models at one HTTPS address. It selects a **Free web service with no persistent disk** for a temporary college demonstration. Accounts and records can disappear on restart, redeploy, or idle shutdown. Memory usage still needs measurement under your traffic; this is a starting configuration, not a capacity guarantee.

## 1. Push the project to GitHub

Create an empty **private** GitHub repository. In PowerShell at `D:\SEM_5\ISC\ISC_PROJECT`:

```powershell
git init
git add .
git status --short
```

Review the staged files before committing. The dataset, virtual environment, node_modules, local databases, encryption keys, and .env files must not appear. Both `SecureMed_AI/securemed_model.pth` and `SecureMed_AI/securemed_resnet18.pth` should appear; they are needed for predictions. `.gitignore` does not remove secrets already committed to history.

```powershell
git commit -m "Prepare SecureMed for Render"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Replace the repository URL. If Git is already initialized or a remote already exists, skip the corresponding setup command. Do not upload your entire project folder through the browser: use Git so the ignore rules apply.

## 2. Create a Render Blueprint

1. Sign in to Render and choose **New > Blueprint**.
2. Connect the private GitHub repository and select the `main` branch.
3. Render reads the root `render.yaml`. Confirm the Free plan and no disk, then create the service.
4. Wait for the Docker build and health check to finish. Open the generated HTTPS URL.

The Docker build compiles React and installs CPU-only PyTorch. Render generates `SECUREMED_ENCRYPTION_KEY` as a base64-encoded 32-byte secret. The application automatically uses `RENDER_EXTERNAL_URL` to allow its hostname and origin. SQLite lives at `/tmp/securemed/securemed_web.db` on temporary storage. Run only one instance/worker because temporary prediction drafts are in memory.

This starts a **new cloud database**; it does not migrate local accounts or records. Preserve a protected backup of the cloud encryption secret alongside database backups. Do not regenerate the key while retaining encrypted data. Do not copy the Windows `.dpapi` key file to Linux.

## 3. Accounts on the free demo

After pushing the updated code, open Render > your service > Environment and add:

- `SECUREMED_ADMIN_USERNAME`: choose a username (3-40 letters, numbers, underscores or hyphens).
- `SECUREMED_ADMIN_PASSWORD`: choose a unique password (12-256 characters).

Save and redeploy. On startup, the server creates the sole administrator if none exists, hashes the password, and records safe audit metadata. Use the normal website sign-in page. There is no public admin registration. An existing admin is never overwritten, and an existing patient username is never promoted. Changing these variables does not reset an existing admin password.

Keep these values in Render's environment settings for this temporary demo: if Render discards the database, startup can recreate the admin. Patient records are not restored. Never put these credentials in source code, GitHub, or a VITE_ frontend variable. Free services have no Shell access.

For an existing service created manually (not from a Blueprint), updating render.yaml does not configure its dashboard settings. Select Free, leave Docker Command blank to use the Dockerfile, and configure:

- `SECUREMED_HTTPS=1`
- `SECUREMED_DB_PATH=/tmp/securemed/securemed_web.db`
- `SECUREMED_ENCRYPTION_KEY`: a base64-encoded 32-byte random secret. Generate it locally using the command below and paste it only into Render's secret environment field. Do not commit or share it.

```powershell
.\.venv\Scripts\python.exe -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Render supplies `RENDER_EXTERNAL_URL` automatically. Preserve the encryption key across deployments.

## 4. Verify the deployed service

- Confirm `/api/status` responds and both models are available after patient login.
- Create a fictional patient, save details, run a prediction, and explicitly save it.
- Confirm a different patient cannot access that record.
- Expect records to be lost after a service restart. Recreate fictional data for the presentation.
- Check the admin storage dashboard and monitor memory usage during predictions.

For a custom domain, set `SECUREMED_ORIGIN=https://your-domain.example` and redeploy. Use the custom domain consistently for API requests and sign-in.

The local API tests and frontend build can be checked before pushing:

```powershell
.\.venv\Scripts\python.exe -B SecureMed_AI\website\test_api.py
npm.cmd --prefix SecureMed_AI/website run build
```

This is a fictional-data educational demonstration, not a clinical service. Cloud deployment and the Docker image must be verified on Render; local tests alone do not establish production readiness.

Official references: https://render.com/docs/blueprint-spec and https://render.com/docs/disks
