[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BinaryPath,

    [string]$ServiceName = 'IPMS Agent',

    [string]$DisplayName = 'IPMS Agent',

    [ValidateSet('Automatic', 'Manual')]
    [string]$StartMode = 'Automatic'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated PowerShell session is required to install the IPMS Agent service.'
}

$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    throw "The service '$ServiceName' already exists. Do not overwrite an existing agent; uninstall or upgrade it through the versioned installer."
}

$startType = if ($StartMode -eq 'Automatic') { 'auto' } else { 'demand' }
if ($PSCmdlet.ShouldProcess($ServiceName, 'Create LocalSystem Windows service')) {
    & sc.exe create $ServiceName binPath= ('"{0}"' -f $resolvedBinary) start= $startType DisplayName= $DisplayName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE." }
    & sc.exe description $ServiceName 'IPMS read-only infrastructure inventory agent.' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe description failed with exit code $LASTEXITCODE." }
}

$installedService = Get-CimInstance -ClassName Win32_Service |
    Where-Object { $_.Name -eq $ServiceName }
if (-not $installedService -or $installedService.StartName -ne 'LocalSystem') {
    throw "The service '$ServiceName' was not installed as LocalSystem."
}
$installedService | Select-Object Name, DisplayName, StartMode, StartName, State
