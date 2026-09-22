$ErrorActionPreference = 'Stop'

$port = if ($env:TRIAGE_PORT) { $env:TRIAGE_PORT } else { '18083' }
$env:TRIAGE_PORT = $port

try {
    docker compose up --build -d
    $health = Invoke-RestMethod "http://127.0.0.1:$port/health"
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
    docker compose down -v
}
