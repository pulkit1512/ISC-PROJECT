$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:PYTHONDONTWRITEBYTECODE = '1'
if (-not (Test-Path 'SecureMed_AI/website/dist/index.html')) {
    Push-Location 'SecureMed_AI/website'
    try { & npm.cmd run build; if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' } }
    finally { Pop-Location }
}
& ./.venv/Scripts/python.exe -B -m uvicorn api:create_app --factory --app-dir SecureMed_AI/website --host 127.0.0.1 --port 8000 --no-access-log
exit $LASTEXITCODE
