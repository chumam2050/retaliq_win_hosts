param(
    [string] $ProjectPath = "..\RetaliqHosts.csproj",
    [string] $OutputRoot = "..\build",
    [string[]] $RIDs = @("win-x64","win-x86"),
    [string] $Configuration = "Release",
    [bool] $SelfContained = $true,
    [switch] $Force
)

function Resolve-ProjectPath($p) {
    # Try resolving the path as given
    try {
        return (Resolve-Path -Path $p -ErrorAction Stop).Path
    }
    catch {
        # If not found, try resolving relative to the script directory
        if ($PSCommandPath) {
            $scriptDir = Split-Path -Parent $PSCommandPath
            $candidate = Join-Path $scriptDir $p
            try { return (Resolve-Path -Path $candidate -ErrorAction Stop).Path } catch { }

            # Also try one level up from the script directory
            $candidate2 = Join-Path (Join-Path $scriptDir '..') $p
            try { return (Resolve-Path -Path $candidate2 -ErrorAction Stop).Path } catch { }
        }

        Write-Error "Project path '$p' not found."
        exit 1
    }
}

$proj = Resolve-ProjectPath $ProjectPath
$rootOut = Resolve-Path -Path $OutputRoot -ErrorAction SilentlyContinue
if (-not $rootOut) {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}
$rootOut = (Resolve-Path -Path $OutputRoot).Path

Write-Output "Building project: $proj"
Write-Output "Output root: $rootOut"
Write-Output "Configuration: $Configuration"
Write-Output "SelfContained: $SelfContained"

foreach ($rid in $RIDs) {
    $outDir = Join-Path $rootOut $rid
    if (Test-Path $outDir) {
        if ($Force) {
            Write-Output "Removing existing output: $outDir"
            Remove-Item -Recurse -Force -Path $outDir
        }
        else {
            Write-Output "Output exists for $rid at $outDir. Use -Force to overwrite. Skipping."
            continue
        }
    }

    Write-Output "Publishing for runtime identifier: $rid"
    if ($SelfContained) { $sc = 'true' } else { $sc = 'false' }
    $args = @('publish', $proj, '-c', $Configuration, '-r', $rid, '--self-contained', $sc, '-o', $outDir)

    # Run dotnet publish directly so output streams to the console
    & dotnet @args
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Error "dotnet publish failed for $rid (exit $exitCode)."
        exit $exitCode
    }

    Write-Output "Published $rid -> $outDir"
}

Write-Output "All done."
