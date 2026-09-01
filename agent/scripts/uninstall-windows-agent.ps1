[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServiceName = 'IPMS Agent'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated PowerShell session is required to uninstall the IPMS Agent service.'
}

$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\IPMSAgent'
$controlPanelGuid = '{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}'
$controlPanelClassKey = "HKLM:\Software\Classes\CLSID\$controlPanelGuid"
$controlPanelNamespaceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\$controlPanelGuid"
$shortcutDirectory = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\IPMS Agent'
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Verbose "The service '$ServiceName' is not installed."
}

if ($service -and $service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop service')) {
    Stop-Service -Name $ServiceName -ErrorAction Stop
}
if ($service -and $PSCmdlet.ShouldProcess($ServiceName, 'Delete service registration')) {
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
}
if ((Test-Path -LiteralPath $uninstallKey) -and $PSCmdlet.ShouldProcess($uninstallKey, 'Remove Programs and Features registration')) {
    Remove-Item -LiteralPath $uninstallKey -Force
}
if ((Test-Path -LiteralPath $shortcutDirectory) -and $PSCmdlet.ShouldProcess($shortcutDirectory, 'Remove Agent Start Menu shortcut')) {
    Remove-Item -LiteralPath $shortcutDirectory -Recurse -Force
}
if ((Test-Path -LiteralPath $controlPanelNamespaceKey) -and $PSCmdlet.ShouldProcess($controlPanelNamespaceKey, 'Remove Agent Control Panel item')) {
    Remove-Item -LiteralPath $controlPanelNamespaceKey -Recurse -Force
}
if ((Test-Path -LiteralPath $controlPanelClassKey) -and $PSCmdlet.ShouldProcess($controlPanelClassKey, 'Remove Agent Control Panel class')) {
    Remove-Item -LiteralPath $controlPanelClassKey -Recurse -Force
}
