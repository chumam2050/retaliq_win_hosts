param(
    [string] $ExePath = "./publish/RetaliqHosts.exe",
    [string] $ServiceName = "RetaliqHosts",
    [string] $DisplayName = "RetaliqHosts Service",
    [string] $Description = "Service that updates Windows hosts based on received payloads",
    [string] $Username = '',
    [string] $Password = ''
)

if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found at $ExePath. Publish the project first to create the binary."
    exit 1
}

# Stop and remove existing service if present
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Output "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Write-Output "Removing existing service..."
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# If a username is provided, ensure we have a password (prompt if not supplied)
$obj = 'LocalSystem'
$pwdPlain = ''
if (-not [string]::IsNullOrWhiteSpace($Username)) {
    $obj = $Username
    if ([string]::IsNullOrWhiteSpace($Password)) {
        # Prompt for secure password
        $secure = Read-Host -AsSecureString -Prompt "Enter service account password for $Username"
        try {
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $pwdPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
        catch {
            Write-Error "Failed to convert secure password to plain text."
            exit 1
        }
    }
    else {
        $pwdPlain = $Password
    }
}

Write-Output "Creating service $ServiceName pointing to $ExePath"

# Build sc.exe create command
$createArgs = @()
$createArgs += "create `"$ServiceName`""
$createArgs += "binPath= `"$ExePath`""
$createArgs += "DisplayName= `"$DisplayName`""
$createArgs += "start= auto"
$createArgs += "obj= `"$obj`""
if (-not [string]::IsNullOrEmpty($pwdPlain)) {
    $createArgs += "password= `"$pwdPlain`""
}

$cmd = "sc.exe " + ($createArgs -join ' ')
Invoke-Expression $cmd

if ($LASTEXITCODE -eq 0) {
    # Set description if provided
    if (-not [string]::IsNullOrWhiteSpace($Description)) {
        sc.exe description $ServiceName `"$Description`" | Out-Null
    }

    Write-Output "Service created. Starting service..."
    Start-Service -Name $ServiceName
    Write-Output "Service started."
} else {
    Write-Error "Failed to create service"
}
