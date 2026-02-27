param(
    [string] $ServiceName = "RetaliqHosts"
)

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Output "Stopping service $ServiceName..."
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to stop service: $_"
    }

    Write-Output "Removing existing service..."
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}
else {
    Write-Warning "Service $ServiceName not found"
}

Write-Output "Done."
