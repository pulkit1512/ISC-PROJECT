# Deploy SecureMed on Render

This configuration serves React, FastAPI, and both CPU models at one HTTPS address. It creates a **paid Standard web service plus a 1 GB persistent disk**. Review Render's current pricing before confirming. Memory usage still needs measurement under your traffic; this is a starting configuration, not a capacity guarantee.

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
3. Render reads the root `render.yaml`. Review the paid plan and disk cost, then create the resources.
4. Wait for the Docker build and health check to finish. Open the generated HTTPS URL.

The Docker build compiles React and installs CPU-only PyTorch. Render generates `SECUREMED_ENCRYPTION_KEY` as a base64-encoded 32-byte secret. The application automatically uses `RENDER_EXTERNAL_URL` to allow its hostname and origin. SQLite lives at `/data/securemed_web.db` on the persistent disk. Run only one instance/worker because temporary prediction drafts are in memory.

This starts a **new cloud database**; it does not migrate local accounts or records. Preserve a protected backup of the cloud encryption secret alongside database backups. Do not regenerate the key while retaining encrypted data. Do not copy the Windows `.dpapi` key file to Linux.

## 3. Privately create the cloud administrator

Open the service's **Shell** in the Render dashboard and run:

```sh
python -B SecureMed_AI/website/manage_admin.py
```

Choose a username and a password of at least 12 characters. The password prompt is hidden. Sign in using those credentials on the normal website login page. Patient signup cannot create administrators.

## 4. Verify the deployed service

- Confirm `/api/status` responds and both models are available after patient login.
- Create a fictional patient, save details, run a prediction, and explicitly save it.
- Confirm a different patient cannot access that record.
- Restart the service and confirm the saved record remains accessible.
- Check the admin storage dashboard and monitor memory usage during predictions.

For a custom domain, set `SECUREMED_ORIGIN=https://your-domain.example` and redeploy. Use the custom domain consistently for API requests and sign-in.

The local API tests and frontend build can be checked before pushing:

```powershell
.\.venv\Scripts\python.exe -B SecureMed_AI\website\test_api.py
npm.cmd --prefix SecureMed_AI/website run build
```

This is a fictional-data educational demonstration, not a clinical service. Cloud deployment and the Docker image must be verified on Render; local tests alone do not establish production readiness.

Official references: https://render.com/docs/blueprint-spec and https://render.com/docs/disks
