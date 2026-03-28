param(
    [ValidateSet("conservative", "balanced", "aggressive")]
    [string]$Profile = "balanced"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$profileFile = Join-Path $repoRoot "deploy\risk_profiles\$Profile.env"
$envFile = Join-Path $repoRoot "backend\.env"
$envExample = Join-Path $repoRoot "backend\.env.example"

if (-not (Test-Path $profileFile)) {
    throw "Risk profile file not found: $profileFile"
}

if (-not (Test-Path $envFile)) {
    if (-not (Test-Path $envExample)) {
        throw "backend\.env and backend\.env.example are both missing."
    }
    Copy-Item $envExample $envFile
}

$profilePairs = @{}
Get-Content $profileFile | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) {
        return
    }
    $parts = $line -split "=", 2
    if ($parts.Count -ne 2) {
        return
    }
    $profilePairs[$parts[0].Trim()] = $parts[1].Trim()
}

$content = Get-Content $envFile
$foundKeys = @{}

for ($i = 0; $i -lt $content.Count; $i++) {
    foreach ($key in $profilePairs.Keys) {
        $prefix = $key + "="
        if ($content[$i].StartsWith($prefix)) {
            $content[$i] = $key + "=" + $profilePairs[$key]
            $foundKeys[$key] = $true
            break
        }
    }
}

foreach ($key in $profilePairs.Keys) {
    if (-not $foundKeys.ContainsKey($key)) {
        $content += ($key + "=" + $profilePairs[$key])
    }
}

Set-Content -Path $envFile -Value $content

Write-Output "Applied risk profile '$Profile' to backend\.env"
Write-Output "Profile source: $profileFile"
