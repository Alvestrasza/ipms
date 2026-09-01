[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BinaryPath,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ConfigBinaryPath,

    [string]$ServiceName = 'IPMS Agent',

    [string]$DisplayName = 'IPMS Agent',

    [string]$AgentVersion = '0.1.21',

    [string]$Publisher = 'Alvestrasza Corporation',

    [ValidateSet('Automatic', 'Manual')]
    [string]$StartMode = 'Automatic'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated PowerShell session is required to install the IPMS Agent service.'
}

$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
$resolvedConfigBinary = (Resolve-Path -LiteralPath $ConfigBinaryPath).Path
$agentDirectory = Split-Path -Path $resolvedBinary -Parent
if ((Split-Path -Path $resolvedConfigBinary -Parent) -ne $agentDirectory) {
    throw 'The Agent service and configuration application must be installed in the same directory.'
}
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    throw "The service '$ServiceName' already exists. Do not overwrite an existing agent; uninstall or upgrade it through the versioned installer."
}

if ($WhatIfPreference) {
    Write-Information "WhatIf: would install '$ServiceName' as LocalSystem, protect the Agent configuration directory, and register the configuration application."
    return
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

$configurationDirectory = Join-Path $env:ProgramData 'Alvestrasza\IPMS Agent'
if ($PSCmdlet.ShouldProcess($configurationDirectory, 'Create protected Agent configuration directory')) {
    New-Item -ItemType Directory -Path $configurationDirectory -Force | Out-Null
    & icacls.exe $configurationDirectory /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls.exe failed with exit code $LASTEXITCODE." }
}

$installedUninstaller = Join-Path $agentDirectory 'ipms-agent-uninstall.ps1'
$uninstallerSource = Join-Path $PSScriptRoot 'uninstall-windows-agent.ps1'
if ($PSCmdlet.ShouldProcess($installedUninstaller, 'Install Agent uninstaller')) {
    Copy-Item -LiteralPath $uninstallerSource -Destination $installedUninstaller -Force
}
$installedEnrollmentImporter = Join-Path $agentDirectory 'ipms-agent-import-enrollment.ps1'
$enrollmentImporterSource = Join-Path $PSScriptRoot 'import-windows-agent-enrollment.ps1'
if ($PSCmdlet.ShouldProcess($installedEnrollmentImporter, 'Install Agent enrollment importer')) {
    Copy-Item -LiteralPath $enrollmentImporterSource -Destination $installedEnrollmentImporter -Force
}

$shortcutDirectory = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\IPMS Agent'
$shortcutPath = Join-Path $shortcutDirectory 'IPMS Agent Configuration.lnk'
if ($PSCmdlet.ShouldProcess($shortcutPath, 'Create Agent configuration shortcut')) {
    New-Item -ItemType Directory -Path $shortcutDirectory -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $resolvedConfigBinary
    $shortcut.WorkingDirectory = $agentDirectory
    $shortcut.Description = 'Configure the IPMS Agent gateway and trust mode.'
    $shortcut.Save()
}

$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\IPMSAgent'
$controlPanelGuid = '{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}'
$controlPanelClassKey = "HKLM:\Software\Classes\CLSID\$controlPanelGuid"
$controlPanelNamespaceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\$controlPanelGuid"
if ($PSCmdlet.ShouldProcess($uninstallKey, 'Register Agent in Programs and Features')) {
    New-Item -Path $uninstallKey -Force | Out-Null
    $powerShellHost = Join-Path $PSHOME 'pwsh.exe'
    if (-not (Test-Path -LiteralPath $powerShellHost -PathType Leaf)) {
        $powerShellHost = (Get-Command -Name powershell.exe -ErrorAction Stop).Source
    }
    $uninstallCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $powerShellHost, $installedUninstaller
    New-ItemProperty -Path $uninstallKey -Name DisplayName -Value 'IPMS Agent' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $AgentVersion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name Publisher -Value $Publisher -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $agentDirectory -PropertyType String -Force | Out-Null
    $estimatedSizeKb = [math]::Ceiling(((Get-Item -LiteralPath $resolvedBinary).Length + (Get-Item -LiteralPath $resolvedConfigBinary).Length + (Get-Item -LiteralPath $installedUninstaller).Length + (Get-Item -LiteralPath $installedEnrollmentImporter).Length) / 1KB)
    New-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value ($resolvedConfigBinary + ',0') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name ModifyPath -Value ('"{0}"' -f $resolvedConfigBinary) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name URLInfoAbout -Value 'https://www.alvestrasza.com' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name EstimatedSize -Value $estimatedSizeKb -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoModify -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallKey -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

if ($PSCmdlet.ShouldProcess($controlPanelNamespaceKey, 'Register IPMS Agent Configuration in Control Panel')) {
    New-Item -Path $controlPanelClassKey -Force | Out-Null
    Set-Item -LiteralPath $controlPanelClassKey -Value 'IPMS Agent Configuration'
    New-ItemProperty -Path $controlPanelClassKey -Name InfoTip -Value 'Configure the IPMS Agent management endpoint and trust mode.' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $controlPanelClassKey -Name 'System.ApplicationName' -Value 'Alvestrasza.IPMSAgent.Configuration' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $controlPanelClassKey -Name 'System.ControlPanel.Category' -Value '5' -PropertyType String -Force | Out-Null
    $defaultIconKey = Join-Path $controlPanelClassKey 'DefaultIcon'
    New-Item -Path $defaultIconKey -Force | Out-Null
    Set-Item -LiteralPath $defaultIconKey -Value ($resolvedConfigBinary + ',0')
    $openCommandKey = Join-Path $controlPanelClassKey 'Shell\Open\Command'
    New-Item -Path $openCommandKey -Force | Out-Null
    Set-Item -LiteralPath $openCommandKey -Value ('"{0}"' -f $resolvedConfigBinary)
    New-Item -Path $controlPanelNamespaceKey -Force | Out-Null
    Set-Item -LiteralPath $controlPanelNamespaceKey -Value 'IPMS Agent Configuration'
}

if (-not (Test-Path -LiteralPath $uninstallKey)) {
    throw 'The Programs and Features registration could not be verified.'
}
$installedService | Select-Object Name, DisplayName, StartMode, StartName, State
