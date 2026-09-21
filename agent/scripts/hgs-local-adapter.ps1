# File Name: hgs-local-adapter.ps1
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Release-embedded HGS adapter. Only the native validated request file is accepted.
# This source is embedded into ipms-agent at build time. It is not downloaded by a Management Pack.
param([Parameter(Mandatory = $true)][string]$RequestPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')

function Import-SystemModule([string]$Name) {
    # Calls use only names compiled into this script, never request-selected names.
    Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules', $Name)) -ErrorAction Stop
}
Import-SystemModule 'Microsoft.PowerShell.Management'
Import-SystemModule 'Microsoft.PowerShell.Utility'
Import-SystemModule 'Microsoft.PowerShell.Security'
Import-SystemModule 'CimCmdlets'
Add-Type -AssemblyName System.Security

function Assert-ProtectedFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) { throw 'hgs_storage_invalid' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'hgs_storage_invalid' }
    foreach ($entry in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($entry.AccessControlType -eq 'Allow' -and $entry.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'hgs_storage_invalid' }
    }
}
function Test-LocalSource([string]$Path) {
    try {
        if ($Path -notmatch '^[A-Za-z]:\\[^:]*$' -or $Path.Contains('..')) { return $false }
        if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path)).DriveType -notin @('Fixed', 'Removable', 'CDRom', 'Ram')) { return $false }
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) { return $false }
        while ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            $item = $item.Parent
        }
        return $true
    } catch { return $false }
}
function Read-LocalSecret([string]$Reference, [string]$Purpose) {
    if ($Reference -notmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'hgs_secret_invalid' }
    $path = Join-Path $script:SecretDirectory ($Reference + '.json')
    Assert-ProtectedFile $path
    $text = [IO.File]::ReadAllText($path)
    if ($text.Length -gt 16384) { throw 'hgs_secret_invalid' }
    $secret = $text | ConvertFrom-Json
    if ($secret.schema_version -ne 1 -or $secret.purpose -cne $Purpose -or $secret.tenant_id -cne $script:Job.tenant_id -or $secret.device_uri -cne $script:Job.device_uri) { throw 'hgs_secret_invalid' }
    $entropy = [Text.Encoding]::UTF8.GetBytes('IPMS-HGS-v1|' + $secret.purpose + '|' + $secret.tenant_id + '|' + $secret.device_uri)
    $clear = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($secret.protected_value), $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    try {
        if ($clear.Length -lt 2 -or $clear.Length -gt 8192 -or ($clear.Length % 2) -ne 0) { throw 'hgs_secret_invalid' }
        $value = New-Object Security.SecureString
        for ($i = 0; $i -lt $clear.Length; $i += 2) { $value.AppendChar([char]([int]$clear[$i] + 256 * [int]$clear[$i + 1])) }
        $value.MakeReadOnly()
        if ($Purpose -eq 'join') { return [Management.Automation.PSCredential]::new([string]$secret.username, $value) }
        return $value
    } finally { [Array]::Clear($clear, 0, $clear.Length) }
}
function Test-Secret([string]$Reference, [string]$Purpose) {
    try {
        $value = Read-LocalSecret $Reference $Purpose
        if ($value -is [Security.SecureString]) { $value.Dispose() } else { $value.Password.Dispose() }
        return $true
    } catch { return $false }
}
function Test-PrivateKey([string]$Thumbprint, [bool]$Signing) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
    $rsa = $null
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $certs = @($store.Certificates | Where-Object { $_.Thumbprint -ceq $Thumbprint })
        if ($certs.Count -ne 1) { return $false }
        $cert = $certs[0]
        if (-not $cert.HasPrivateKey -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { return $false }
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($null -eq $rsa -or $rsa.KeySize -lt 2048) { return $false }
        $probe = [Text.Encoding]::UTF8.GetBytes('IPMS-HGS-local-key-access-v1')
        if ($Signing) {
            $signature = $rsa.SignData($probe, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            return $rsa.VerifyData($probe, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        $encrypted = $rsa.Encrypt($probe, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
        $plain = $rsa.Decrypt($encrypted, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
        return [Convert]::ToBase64String($probe) -ceq [Convert]::ToBase64String($plain)
    } catch { return $false } finally { if ($null -ne $rsa) { $rsa.Dispose() }; $store.Close() }
}
function Get-Property($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }; return $property.Value
}
function Resolve-HgsFeatures([array]$ServerFeatures, [array]$DismFeatures, [bool]$LimitAccessSupported) {
    # Jobs cannot select features. Follow only the OS-declared dependency closure
    # of these compiled HGS components and management tools. Unknown metadata is
    # a provider blocker; never substitute an online ServerManager installation.
    if (-not $LimitAccessSupported) { throw 'hgs_offline_provider_unavailable' }
    $required = @('HostGuardianServiceRole', 'AD-Domain-Services', 'DNS', 'Failover-Clustering',
        'Web-Server', 'Web-Asp-Net45', 'Web-Windows-Auth', 'Web-Scripting-Tools',
        'RSAT-AD-PowerShell', 'RSAT-Clustering-PowerShell', 'RSAT-HostGuardianService', 'NET-WCF-HTTP-Activation45')
    $roles = @{}; $optional = @{}
    foreach ($feature in $ServerFeatures) {
        $name = [string](Get-Property $feature 'Name')
        if ($roles.ContainsKey($name)) { throw 'hgs_offline_provider_unavailable' }
        $roles[$name] = $feature
    }
    foreach ($feature in $DismFeatures) { $optional[[string](Get-Property $feature 'FeatureName')] = $true }
    $visited = @{}; $names = @{}; $installed = $true
    $queue = [Collections.Generic.Queue[string]]::new()
    foreach ($name in $required) { $queue.Enqueue($name) }
    while ($queue.Count -gt 0) {
        $name = $queue.Dequeue()
        if ($visited.ContainsKey($name)) { continue }
        if ($visited.Count -ge 128 -or -not $roles.ContainsKey($name)) { throw 'hgs_offline_provider_unavailable' }
        $visited[$name] = $true; $feature = $roles[$name]
        $state = Get-Property $feature 'Installed'
        if ($state -isnot [bool]) { throw 'hgs_offline_provider_unavailable' }
        if (-not $state) { $installed = $false }
        $installName = [string](Get-Property (Get-Property $feature 'AdditionalInfo') 'InstallName')
        if ($installName -notmatch '^[A-Za-z0-9_.-]{1,128}$' -or -not $optional.ContainsKey($installName)) { throw 'hgs_offline_provider_unavailable' }
        $names[$installName] = $true
        foreach ($dependency in @(Get-Property $feature 'DependsOn')) {
            if ($null -eq $dependency) { continue }
            $dependencyName = $(if ($dependency -is [string]) { $dependency } else { [string](Get-Property $dependency 'Name') })
            if ($dependencyName -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'hgs_offline_provider_unavailable' }
            $queue.Enqueue($dependencyName)
        }
    }
    return @{ installed = [bool]$installed; names = [string[]]@($names.Keys | Sort-Object) }
}
function Read-HgsFeatures {
    $enable = Get-Command -Name 'Dism\Enable-WindowsOptionalFeature' -CommandType Cmdlet
    $offline = $enable.Parameters.ContainsKey('LimitAccess') -and $enable.Parameters.ContainsKey('Source') -and $enable.Parameters.ContainsKey('NoRestart') -and $enable.Parameters.ContainsKey('All')
    return Resolve-HgsFeatures @(ServerManager\Get-WindowsFeature) @(Dism\Get-WindowsOptionalFeature -Online) $offline
}
function Get-HgsServiceSid {
    Import-SystemModule 'IISAdministration'
    $pool = IISAdministration\Get-IISAppPool -Name 'KeyProtection'
    $account = [string]$pool.ProcessModel.UserName
    if ($account -notmatch '^[A-Za-z0-9.-]+\\[A-Za-z0-9._-]+\$$') { throw 'hgs_service_identity_invalid' }
    return [Security.Principal.NTAccount]::new($account).Translate([Security.Principal.SecurityIdentifier])
}
function Get-CertificateKeyPath([string]$Thumbprint) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine'); $rsa = $null
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $certs = @($store.Certificates | Where-Object { $_.Thumbprint -ceq $Thumbprint })
        if ($certs.Count -ne 1) { throw 'hgs_key_access_unavailable' }
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certs[0])
        if ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            if (-not $rsa.CspKeyContainerInfo.MachineKeyStore) { throw 'hgs_key_access_unavailable' }
            $name = $rsa.CspKeyContainerInfo.UniqueKeyContainerName
            $parent = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'Microsoft', 'Crypto', 'RSA', 'MachineKeys')
        } elseif ($rsa -is [Security.Cryptography.RSACng]) {
            if (-not $rsa.Key.IsMachineKey) { throw 'hgs_key_access_unavailable' }
            $name = $rsa.Key.UniqueName
            $parent = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'Microsoft', 'Crypto', 'Keys')
        } else { throw 'hgs_key_access_unavailable' }
        if ($name -notmatch '^[A-Za-z0-9_-]{1,200}$') { throw 'hgs_key_access_unavailable' }
        $path = [IO.Path]::Combine($parent, $name)
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'hgs_key_access_unavailable' }
        $ancestor = $item.Directory
        while ($null -ne $ancestor) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'hgs_key_access_unavailable' }
            $ancestor = $ancestor.Parent
        }
        return $path
    } finally { if ($null -ne $rsa) { $rsa.Dispose() }; $store.Close() }
}
function Test-ServiceKeyAccess([string]$Thumbprint, [Security.Principal.SecurityIdentifier]$Sid) {
    try {
        $path = Get-CertificateKeyPath $Thumbprint
        $acl = Get-Acl -LiteralPath $path
        $allowed = 0; $required = [int][Security.AccessControl.FileSystemRights]::Read
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            # Fail closed for any read denial; unknown group membership cannot make a positive claim.
            if ($rule.AccessControlType -eq 'Deny' -and ([int]$rule.FileSystemRights -band $required) -ne 0) { return $false }
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ceq $Sid.Value) { $allowed = $allowed -bor [int]$rule.FileSystemRights }
        }
        return ($allowed -band $required) -eq $required
    } catch { return $false }
}
function Grant-HgsKeyRead {
    # The account comes only from the locally configured fixed HGS application pool;
    # key paths come only from the two exact certificate key providers.
    $sid = Get-HgsServiceSid
    foreach ($thumb in @($script:Config.signing_thumbprint, $script:Config.encryption_thumbprint)) {
        if (-not (Test-ServiceKeyAccess $thumb $sid)) {
            $path = Get-CertificateKeyPath $thumb
            $acl = Get-Acl -LiteralPath $path
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::Read, [Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
            if (-not (Test-ServiceKeyAccess $thumb $sid)) { throw 'hgs_key_access_unavailable' }
        }
    }
}
function Read-Observation {
    $os = CimCmdlets\Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 15
    $computer = CimCmdlets\Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 15
    $supported = $os.ProductType -ne 1 -and [string]$os.BuildNumber -in @('20348', '26100')
    $roleInstalled = $false; $initialized = $false; $mode = 'none'; $healthy = $false; $modeSupported = $supported; $offlineReady = $false
    $configuredService = ''; $configuredSigning = ''; $configuredEncryption = ''; $serviceKeys = $false
    $pending = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $session = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if ($null -ne (Get-Property $session 'PendingFileRenameOperations')) { $pending = $true }
    $active = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
    $next = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    if ($active.ComputerName -cne $next.ComputerName) { $pending = $true }
    if ($supported) {
        Import-SystemModule 'ServerManager'
        Import-SystemModule 'Dism'
        try {
            $features = Read-HgsFeatures
            $roleInstalled = [bool]$features.installed
            $offlineReady = $true
        } catch { $modeSupported = $false }
        if ($roleInstalled) {
            Import-SystemModule 'HgsServer'
            $command = Get-Command -Name 'HgsServer\Initialize-HgsServer' -CommandType Function, Cmdlet
            $modeSupported = $script:Config.attestation_mode -eq 'tpm' -or $command.Parameters.ContainsKey('TrustHostKey')
            try {
                $hgs = HgsServer\Get-HgsServer
                switch ([string](Get-Property $hgs 'AttestationOperationMode')) { 'Tpm' { $mode = 'tpm' }; 'HostKey' { $mode = 'host_key' } }
                $attestation = @(Get-Property $hgs 'AttestationUrl'); $protection = @(Get-Property $hgs 'KeyProtectionUrl')
                $initialized = $mode -ne 'none' -and $attestation.Count -gt 0 -and $protection.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$protection[0])
                if ($initialized) {
                    $observedUrl = [Uri]([string]$protection[0]); $observedAttestation = [Uri]([string]$attestation[0])
                    if ($observedUrl.AbsolutePath.TrimEnd('/') -ine '/KeyProtection' -or $observedAttestation.AbsolutePath.TrimEnd('/') -ine '/Attestation' -or $observedUrl.DnsSafeHost -ine $observedAttestation.DnsSafeHost) { throw 'hgs_service_identity_invalid' }
                    $configuredService = $observedUrl.DnsSafeHost.ToLowerInvariant()
                    $domainSuffix = '.' + ([string]$computer.Domain).ToLowerInvariant()
                    if ($configuredService.EndsWith($domainSuffix)) { $configuredService = $configuredService.Substring(0, $configuredService.Length - $domainSuffix.Length) }
                    Import-SystemModule 'HgsKeyProtection'
                    $signing = @(HgsKeyProtection\Get-HgsKeyProtectionCertificate -CertificateType Signing -IsEnabled $true -IsPrimary $true)
                    $encryption = @(HgsKeyProtection\Get-HgsKeyProtectionCertificate -CertificateType Encryption -IsEnabled $true -IsPrimary $true)
                    if ($signing.Count -eq 1) { $configuredSigning = ([string]$signing[0].Thumbprint).ToUpperInvariant() }
                    if ($encryption.Count -eq 1) { $configuredEncryption = ([string]$encryption[0].Thumbprint).ToUpperInvariant() }
                    $serviceSid = Get-HgsServiceSid
                    $serviceKeys = (Test-ServiceKeyAccess $configuredSigning $serviceSid) -and (Test-ServiceKeyAccess $configuredEncryption $serviceSid)
                    # This is an exact loopback URL. No remotely supplied or reflected URL is fetched.
                    $client = [Net.HttpWebRequest]::Create('http://127.0.0.1/KeyProtection/service/metadata/2014-07/metadata.xml')
                    $client.Proxy = $null; $client.AllowAutoRedirect = $false; $client.Timeout = 10000; $client.ReadWriteTimeout = 10000
                    $response = $client.GetResponse()
                    try { $healthy = [int]$response.StatusCode -eq 200 } finally { $response.Close() }
                    $healthy = $healthy -and (Get-Service -Name W3SVC).Status -eq 'Running' -and (Get-Service -Name ClusSvc).Status -eq 'Running'
                }
            } catch { $healthy = $false }
        }
    }
    $signReady = Test-PrivateKey $script:Config.signing_thumbprint $true
    $encReady = Test-PrivateKey $script:Config.encryption_thumbprint $false
    return [ordered]@{
        os_build = [string]$os.BuildNumber; is_server = [bool]($os.ProductType -ne 1); computer_name = [string]$computer.Name
        domain_name = $(if ($computer.PartOfDomain) { ([string]$computer.Domain).ToLowerInvariant() } else { '' }); domain_joined = [bool]$computer.PartOfDomain; domain_role = [int]$computer.DomainRole
        role_installed = [bool]$roleInstalled; service_initialized = [bool]$initialized; attestation_mode = $mode
        signing_certificate_ready = [bool]$signReady; encryption_certificate_ready = [bool]$encReady
        feature_source_ready = [bool](Test-LocalSource $script:Config.feature_source)
        dsrm_secret_ready = [bool](Test-Secret $script:Config.dsrm_secret_ref 'dsrm'); join_secret_ready = [bool](Test-Secret $script:Config.join_secret_ref 'join')
        reboot_pending = [bool]$pending; boot_id = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        service_healthy = [bool]$healthy; key_access_verified = [bool]($serviceKeys -and $signReady -and $encReady); mode_supported = [bool]$modeSupported; offline_source_policy_ready = [bool]$offlineReady
        configured_service_name = $configuredService; configured_signing_thumbprint = $configuredSigning; configured_encryption_thumbprint = $configuredEncryption
    }
}
try {
    Assert-ProtectedFile $RequestPath
    $requestText = [IO.File]::ReadAllText($RequestPath)
    if ($requestText.Length -gt 65536) { throw 'hgs_contract_invalid' }
    $request = $requestText | ConvertFrom-Json
    $script:Job = $request.assignment; $script:Config = $script:Job.config
    $script:SecretDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Alvestrasza\IPMS Agent\hgs\secrets'
    if ($request.mode -notin @('inspect', 'apply') -or $script:Job.operation -notin @('inspect', 'install_role', 'create_forest', 'join_node', 'initialize', 'verify', 'reboot')) { throw 'hgs_contract_invalid' }
    $observation = Read-Observation
    if ($request.mode -eq 'inspect') { [Console]::Out.Write(($observation | ConvertTo-Json -Compress -Depth 4)); exit 0 }
    if (-not $observation.is_server -or $observation.os_build -notin @('20348', '26100') -or -not $observation.mode_supported) { throw 'hgs_unsupported_platform' }
    if ($script:Job.expires_at -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { throw 'hgs_job_expired' }
    $needsReboot = $false
    switch ($script:Job.operation) {
        'install_role' {
            if ($observation.domain_joined -or -not $observation.feature_source_ready -or -not $observation.offline_source_policy_ready) { throw 'hgs_prerequisite_failed' }
            # DISM LimitAccess is mandatory; ServerManager alone can fall back to Windows Update.
            $features = Read-HgsFeatures
            $installed = Dism\Enable-WindowsOptionalFeature -Online -FeatureName $features.names -All -Source $script:Config.feature_source -LimitAccess -NoRestart -ErrorAction Stop
            $needsReboot = @($installed | Where-Object { $_.RestartNeeded }).Count -gt 0
        }
        'create_forest' {
            if ($observation.domain_joined -or -not $observation.role_installed -or $observation.reboot_pending -or $script:Config.node_role -ne 'primary') { throw 'hgs_prerequisite_failed' }
            $dsrm = Read-LocalSecret $script:Config.dsrm_secret_ref 'dsrm'
            try { HgsServer\Install-HgsServer -HgsDomainName $script:Config.domain_name -SafeModeAdministratorPassword $dsrm -Restart:$false -Confirm:$false | Out-Null } finally { $dsrm.Dispose() }
            $needsReboot = $true
        }
        'join_node' {
            if ($observation.domain_joined -or -not $observation.role_installed -or $observation.reboot_pending -or $script:Config.node_role -ne 'additional') { throw 'hgs_prerequisite_failed' }
            $dsrm = Read-LocalSecret $script:Config.dsrm_secret_ref 'dsrm'; $credential = Read-LocalSecret $script:Config.join_secret_ref 'join'
            try { HgsServer\Install-HgsServer -HgsDomainName $script:Config.domain_name -HgsDomainCredential $credential -SafeModeAdministratorPassword $dsrm -Restart:$false -Confirm:$false | Out-Null } finally { $dsrm.Dispose(); $credential.Password.Dispose() }
            $needsReboot = $true
        }
        'initialize' {
            if (-not $observation.role_installed -or -not $observation.domain_joined -or $observation.domain_name -cne $script:Config.domain_name -or $observation.domain_role -lt 4 -or $observation.reboot_pending -or -not $observation.signing_certificate_ready -or -not $observation.encryption_certificate_ready) { throw 'hgs_prerequisite_failed' }
            if ($observation.service_initialized) { throw 'hgs_reconciliation_required' }
            if ($script:Config.node_role -eq 'additional') {
                $address = $null
                if (-not [Net.IPAddress]::TryParse($script:Config.primary_server, [ref]$address)) { throw 'hgs_contract_invalid' }
                HgsServer\Initialize-HgsServer -HgsServerIPAddress $script:Config.primary_server -Confirm:$false | Out-Null
            } elseif ($script:Config.attestation_mode -eq 'tpm') {
                HgsServer\Initialize-HgsServer -HgsServiceName $script:Config.service_name -SigningCertificateThumbprint $script:Config.signing_thumbprint -EncryptionCertificateThumbprint $script:Config.encryption_thumbprint -TrustTpm -Confirm:$false | Out-Null
            } elseif ($script:Config.profile -eq 'vtpm' -and $script:Config.attestation_mode -eq 'host_key') {
                HgsServer\Initialize-HgsServer -HgsServiceName $script:Config.service_name -SigningCertificateThumbprint $script:Config.signing_thumbprint -EncryptionCertificateThumbprint $script:Config.encryption_thumbprint -TrustHostKey -Confirm:$false | Out-Null
            } else { throw 'hgs_contract_invalid' }
            Grant-HgsKeyRead
        }
        # Reboot is native InitiateSystemShutdownExW after durable write intent.
        default { throw 'hgs_contract_invalid' }
    }
    [Console]::Out.Write((@{ applied = $true; reboot_required = [bool]$needsReboot } | ConvertTo-Json -Compress))
} catch {
    # Do not serialize ErrorRecord, cmdlet arguments or exception messages.
    [Console]::Out.Write('{"error":"hgs_provider_failed"}')
    exit 4
}
