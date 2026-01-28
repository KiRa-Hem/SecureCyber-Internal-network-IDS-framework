# Switch the active model profile without editing backend/.env.

param(
    [ValidateSet("cic")]
    [string]$Profile = "cic"
)

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$activePath = Join-Path $repoRoot "models\active_model.json"

$payload = @{ active = $Profile } | ConvertTo-Json -Depth 2
Set-Content -Path $activePath -Value $payload -Encoding UTF8

Write-Output "Active model set to '$Profile' via $activePath"
