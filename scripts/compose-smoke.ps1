$ErrorActionPreference = 'Stop'

$previousPort = $env:TRIAGE_PORT
$port = if ($previousPort) { $previousPort } else { '18083' }
$projectName = 'siem-triage-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot 'compose.yaml'
$env:TRIAGE_PORT = $port

try {
    docker compose --project-directory $repoRoot -f $composeFile -p $projectName up --build -d
    if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed' }
    $health = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 2
            if ($health.status -eq 'ok') { break }
        }
        catch { }
        Start-Sleep -Milliseconds 250
    }
    if ($health.status -ne 'ok') {
        throw "health status was not ok"
    }
    $dashboard = Invoke-WebRequest "http://127.0.0.1:$port/stats"
    if ($dashboard.StatusCode -ne 200 -or -not $dashboard.Content.Contains('Dashboard')) {
        throw "dashboard smoke check failed"
    }
    $incidents = @(Invoke-RestMethod "http://127.0.0.1:$port/api/incidents")
    if ($incidents.Count -lt 1) {
        throw "demo incident was not loaded"
    }
    [pscustomobject]@{
        Health = $health.status
        DashboardStatus = $dashboard.StatusCode
        IncidentCount = $incidents.Count
    } | Format-List
}
finally {
    # Only this newly created project is removed; an existing demo's volume is
    # never part of the smoke test's cleanup scope.
    docker compose --project-directory $repoRoot -f $composeFile -p $projectName down -v
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not clean up temporary project $projectName" }
    $env:TRIAGE_PORT = $previousPort
}
