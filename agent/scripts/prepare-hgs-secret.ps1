# File Name: prepare-hgs-secret.ps1
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Interactive local HGS secret custody, scoped to tenant and enrolled device; no remote secrets.
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$Reference,
    [Parameter(Mandatory = $true)][ValidateSet('dsrm', 'join')][string]$Purpose,
    [Parameter(Mandatory = $true)][Guid]$TenantId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Alvestrasza\IPMS Agent'
$identity = Get-Content -LiteralPath (Join-Path $root 'agent-state.json') -Raw | ConvertFrom-Json
if ($identity.device_uri -notmatch '^urn:ipms:agent:[0-9a-f-]{36}$') { throw 'A valid Agent enrollment is required.' }
$directory = Join-Path $root 'hgs\secrets'
foreach ($path in @($root, (Join-Path $root 'hgs'), $directory)) {
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -ItemType Directory | Out-Null }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse storage is not allowed.' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $path -AclObject $acl
}
$path = Join-Path $directory ($Reference + '.json')
if (Test-Path -LiteralPath $path) { throw 'This reference already exists. Use a new reference; existing custody is not overwritten.' }
$credential = $null
if ($Purpose -eq 'join') { $credential = Get-Credential -Message 'HGS forest domain administrator for this node'; $password = $credential.Password }
else { $password = Read-Host -AsSecureString -Prompt 'Directory Services Restore Mode password' }
if ($null -eq $password -or $password.Length -lt 1) { throw 'A secret is required.' }
$pointer = [IntPtr]::Zero; $clear = $null
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $clear = New-Object byte[] ($password.Length * 2)
    [Runtime.InteropServices.Marshal]::Copy($pointer, $clear, 0, $clear.Length)
    $tenant = $TenantId.ToString().ToLowerInvariant()
    $entropy = [Text.Encoding]::UTF8.GetBytes('IPMS-HGS-v1|' + $Purpose + '|' + $tenant + '|' + $identity.device_uri)
    $protected = [Security.Cryptography.ProtectedData]::Protect($clear, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $document = [ordered]@{ schema_version = 1; purpose = $Purpose; tenant_id = $tenant; device_uri = $identity.device_uri; username = $(if ($null -ne $credential) { $credential.UserName } else { '' }); protected_value = [Convert]::ToBase64String($protected) }
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $fileAcl)
    try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($document | ConvertTo-Json -Compress)); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $saved = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($saved.protected_value -cne $document.protected_value -or $saved.device_uri -cne $identity.device_uri) { throw 'Secret read-back failed.' }
    Write-Host ('Prepared local ' + $Purpose + ' reference: ' + $Reference)
} finally {
    if ($null -ne $clear) { [Array]::Clear($clear, 0, $clear.Length) }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $password.Dispose()
}
