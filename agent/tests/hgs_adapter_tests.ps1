# File Name: hgs_adapter_tests.ps1
# Version: v0.1.0 | Created: 2026-09-20 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Parse packaged helpers and exercise pure offline feature resolution; never run HGS operations.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Assert-Rejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'Unsafe or unavailable feature metadata was accepted.'
}
$adapterPath = Join-Path $PSScriptRoot '..\scripts\hgs-local-adapter.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($adapterPath, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'The embedded HGS adapter does not parse.'
foreach ($helper in @('prepare-hgs-secret.ps1', 'install-windows-agent.ps1')) {
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot ('..\scripts\' + $helper)), [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'The packaged local helper does not parse.'
}
# Import only these two pure functions, never the adapter entrypoint or provider.
foreach ($name in @('Get-Property', 'Resolve-HgsFeatures')) {
    $function = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Assert-True ($function.Count -eq 1) 'The pure feature resolver is missing or ambiguous.'
    . ([scriptblock]::Create($function[0].Extent.Text))
}
$names = @('HostGuardianServiceRole', 'AD-Domain-Services', 'DNS', 'Failover-Clustering',
    'Web-Server', 'Web-Asp-Net45', 'Web-Windows-Auth', 'Web-Scripting-Tools',
    'RSAT-AD-PowerShell', 'RSAT-Clustering-PowerShell', 'RSAT-HostGuardianService', 'NET-WCF-HTTP-Activation45')
$roles = @($names | ForEach-Object { [pscustomobject]@{ Name = $_; Installed = $true; AdditionalInfo = @{ InstallName = ('Fixture-' + $_) }; DependsOn = @() } })
$optional = @($names | ForEach-Object { [pscustomobject]@{ FeatureName = ('Fixture-' + $_) } })
$resolved = Resolve-HgsFeatures $roles $optional $true
Assert-True ($resolved.installed -and $resolved.names.Count -eq 12) 'A complete local feature inventory did not resolve.'
$roles[1].Installed = $false
Assert-True (-not (Resolve-HgsFeatures $roles $optional $true).installed) 'A missing AD DS dependency was accepted as installed.'
$roles[1].Installed = $true
Assert-Rejected { Resolve-HgsFeatures $roles $optional $false }
Assert-Rejected { Resolve-HgsFeatures $roles[1..11] $optional $true }
Assert-Rejected { Resolve-HgsFeatures $roles $optional[1..11] $true }
$roles[0].AdditionalInfo.InstallName = 'unavailable'
Assert-Rejected { Resolve-HgsFeatures $roles $optional $true }
$roles[0].AdditionalInfo.InstallName = 'Fixture-HostGuardianServiceRole'
$roles[0].DependsOn = @('RequiredDependency')
Assert-Rejected { Resolve-HgsFeatures $roles $optional $true }
$dependency = [pscustomobject]@{ Name = 'RequiredDependency'; Installed = $false; AdditionalInfo = @{ InstallName = 'Fixture-Dependency' }; DependsOn = @('HostGuardianServiceRole') }
$withDependency = @($roles) + @($dependency)
$optionalDependency = @($optional) + @([pscustomobject]@{ FeatureName = 'Fixture-Dependency' })
$resolved = Resolve-HgsFeatures $withDependency $optionalDependency $true
Assert-True (-not $resolved.installed -and $resolved.names.Count -eq 13) 'A recursive missing dependency was omitted.'
$dependency.Installed = $true
Assert-True (Resolve-HgsFeatures $withDependency $optionalDependency $true).installed 'A dependency cycle was not bounded by visited identity.'
$calls = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Dism\Enable-WindowsOptionalFeature' }, $true)
Assert-True ($calls.Count -eq 1) 'Feature mutation must use one bounded offline call.'
$parameters = @($calls[0].CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
foreach ($required in @('LimitAccess', 'Source', 'NoRestart', 'All', 'Online', 'FeatureName')) {
    Assert-True ($parameters -contains $required) 'Feature mutation is missing an offline enforcement parameter.'
}
Write-Output 'HGS helper parsing and isolated offline resolver tests passed; no HGS or Windows mutation executed.'
