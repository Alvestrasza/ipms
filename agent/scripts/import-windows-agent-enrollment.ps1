[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EnrollmentDocument
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated PowerShell session is required to import an IPMS Agent enrollment.'
}

$source = (Resolve-Path -LiteralPath $EnrollmentDocument).Path
$document = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
if (-not $document.device_uri.StartsWith('urn:ipms:agent:') -or
    [string]::IsNullOrWhiteSpace($document.gateway_dns_name) -or
    $document.gateway_port -lt 1 -or $document.gateway_port -gt 65535 -or
    $document.gateway_fingerprint_sha256 -notmatch '^[0-9a-fA-F]{64}$' -or
    [string]::IsNullOrWhiteSpace($document.bootstrap_token)) {
    throw 'The enrollment document is invalid.'
}

$directory = Join-Path $env:ProgramData 'Alvestrasza\IPMS Agent'
$destination = Join-Path $directory 'enrollment.json'
if (Test-Path -LiteralPath $destination) {
    throw 'An unconsumed Agent enrollment already exists.'
}
if (Test-Path -LiteralPath (Join-Path $directory 'agent-state.json')) {
    throw 'This Agent is already enrolled. Re-enrollment requires an explicit revocation and reset workflow.'
}

if ($PSCmdlet.ShouldProcess($destination, 'Import one-time Agent enrollment into the protected LocalSystem directory')) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    & icacls.exe $directory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls.exe failed with exit code $LASTEXITCODE." }
    Copy-Item -LiteralPath $source -Destination $destination
    & icacls.exe $destination /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls.exe failed with exit code $LASTEXITCODE." }
}

Write-Output 'The one-time Agent enrollment was imported without displaying its secret.'
