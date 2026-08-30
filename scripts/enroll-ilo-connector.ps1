[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9.-]+$')]
    [string]$HostName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]+$')]
    [string]$TenantSlug,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9 ._-]+$')]
    [string]$DisplayName,

    [Parameter(Mandatory)]
    [ValidatePattern('^https://[A-Za-z0-9.:-]+/$')]
    [ValidateScript({
        $uri = [Uri]$_
        $uri.Scheme -eq 'https' -and -not $uri.UserInfo -and $uri.AbsolutePath -eq '/' -and -not $uri.Query -and -not $uri.Fragment
    })]
    [string]$BaseUrl,

    [Parameter(Mandatory)]
    [ValidatePattern('^(?:[0-9A-Fa-f]{2}:?){32}$')]
    [string]$CertificateSha256,

    [ValidatePattern('^[A-Za-z0-9@._-]+$')]
    [string]$IloUsername = 'ipms_ro',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$SshUsername = 'alice',
    [int]$Port = 22,
    [string]$PrivateKeyPath = (Join-Path $PSScriptRoot '..\.ssh\alice_ipms_ed25519'),
    [string]$KnownHostsPath = (Join-Path $PSScriptRoot '..\.ssh\known_hosts')
)

$ErrorActionPreference = 'Stop'
$fingerprint = $CertificateSha256.Replace(':', '').ToLowerInvariant()
$resolvedKey = (Resolve-Path -LiteralPath $PrivateKeyPath).Path
$resolvedKnownHosts = (Resolve-Path -LiteralPath $KnownHostsPath).Path
$sshArguments = @(
    '-p', $Port,
    '-i', $resolvedKey,
    '-o', "UserKnownHostsFile=$resolvedKnownHosts",
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'BatchMode=yes',
    "$SshUsername@$HostName"
)

$target = "$HostName -> $DisplayName ($BaseUrl)"
if (-not $PSCmdlet.ShouldProcess($target, 'Enroll the pinned read-only iLO endpoint, install its protected credential, and run discovery')) {
    return
}

$enrollCommand = "sudo -n bash -c 'set -a; . /srv/ipms/shared/control-plane.env; set +a; export PYTHONPATH=/srv/ipms/current/services/control-plane/src; exec /srv/ipms/current/services/control-plane/.venv/bin/python /srv/ipms/current/services/control-plane/manage.py enroll_ilo_endpoint --tenant-slug $TenantSlug --display-name `"$DisplayName`" --base-url $BaseUrl --certificate-sha256 $fingerprint'"
$enrollmentJson = & ssh @sshArguments $enrollCommand
if ($LASTEXITCODE -ne 0) {
    throw "iLO endpoint enrollment failed with SSH exit code $LASTEXITCODE."
}
$enrollment = $enrollmentJson | ConvertFrom-Json
if (-not $enrollment.endpoint_id -or -not $enrollment.credential_reference) {
    throw 'The Control Plane returned an invalid enrollment response.'
}

$securePassword = Read-Host -Prompt "Password for iLO account $IloUsername" -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = ''
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    $credentialJson = @{ username = $IloUsername; password = $plainPassword } | ConvertTo-Json -Compress
    $installCommand = "sudo -n bash /srv/ipms/current/deploy/standalone/install-connector-secret.sh --credential-reference $($enrollment.credential_reference)"
    $credentialJson | & ssh @sshArguments $installCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Protected credential installation failed with SSH exit code $LASTEXITCODE."
    }
}
finally {
    $plainPassword = $null
    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
}

$runCommand = "sudo -n -u ipms-control-plane bash -c 'set -a; . /srv/ipms/shared/control-plane.env; set +a; export PYTHONPATH=/srv/ipms/current/services/control-plane/src; exec /srv/ipms/current/services/control-plane/.venv/bin/python /srv/ipms/current/services/control-plane/manage.py run_ilo_discovery --endpoint-id $($enrollment.endpoint_id) --requested-by $SshUsername'"
$discoveryJson = & ssh @sshArguments $runCommand
if ($LASTEXITCODE -ne 0) {
    throw "Read-only iLO discovery failed with SSH exit code $LASTEXITCODE."
}

[pscustomobject]@{
    EndpointId = $enrollment.endpoint_id
    Created = $enrollment.created
    Discovery = ($discoveryJson | ConvertFrom-Json)
}
