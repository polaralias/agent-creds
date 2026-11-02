$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$cargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path -LiteralPath $cargoPath)) { $cargoPath = 'cargo' }
& $cargoPath fmt --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $cargoPath clippy --locked --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $cargoPath test --locked
exit $LASTEXITCODE
