[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^SHA256:[A-Za-z0-9+/]{40,44}={0,2}$')]
    [string]$ExpectedHostKeyFingerprint,

    [Parameter(Mandatory = $true)]
    [string]$ManagementSource,

    [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$AdminUser = 'alice',

    [ValidateSet('development', 'customer', 'production')]
    [string]$Profile = 'development',

    [ValidatePattern('^/[A-Za-z0-9._/-]+$')]
    [string]$DataMount = '/srv/ipms',

    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [ValidateRange(2, 60)]
    [int]$RollbackMinutes = 10,

    [string]$PrivateKeyPath,

    [switch]$SkipPackageUpdate,

    [switch]$ExerciseRollback
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Assert-ManagementSource {
    param([Parameter(Mandatory = $true)][string]$Source)

    $parts = $Source.Split('/', [System.StringSplitOptions]::None)
    if ($parts.Count -gt 2 -or [string]::IsNullOrWhiteSpace($parts[0])) {
        throw 'ManagementSource must be an IPv4 or IPv6 address or CIDR.'
    }

    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
        throw 'ManagementSource must contain a valid IP address.'
    }

    if ($parts.Count -eq 2) {
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix)) {
            throw 'ManagementSource contains an invalid CIDR prefix.'
        }
        $maximum = if (
            $address.AddressFamily -eq
            [System.Net.Sockets.AddressFamily]::InterNetwork
        ) { 32 } else { 128 }
        if ($prefix -lt 0 -or $prefix -gt $maximum) {
            throw "ManagementSource CIDR prefix must be between 0 and $maximum."
        }
    }
    else {
        $prefix = if (
            $address.AddressFamily -eq
            [System.Net.Sockets.AddressFamily]::InterNetwork
        ) { 32 } else { 128 }
    }

    if (
        $address.Equals([System.Net.IPAddress]::Any) -or
        $address.Equals([System.Net.IPAddress]::IPv6Any) -or
        [System.Net.IPAddress]::IsLoopback($address)
    ) {
        throw 'ManagementSource cannot be unspecified or loopback.'
    }
    if (
        $address.AddressFamily -eq
        [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $prefix -lt 24
    ) {
        throw 'An IPv4 management source must be a host or a /24-or-narrower CIDR.'
    }
    if (
        $address.AddressFamily -eq
        [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and
        $prefix -lt 64
    ) {
        throw 'An IPv6 management source must be a host or a /64-or-narrower CIDR.'
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    $output = @(& $Command @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $detail = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        throw "$FailureMessage`n$detail"
    }
    return $output
}

function Invoke-ExpectedSshFailure {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$UnexpectedSuccessMessage
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $null = & ssh @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    if ($exitCode -eq 0) {
        throw $UnexpectedSuccessMessage
    }
}

Assert-ManagementSource -Source $ManagementSource

if ($Profile -ne 'development') {
    throw (
        "The $Profile profile is blocked until the production encryption " +
        'and recovery policy is implemented.'
    )
}

if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
    $PrivateKeyPath = Join-Path $PSScriptRoot '..\.ssh\alice_ipms_ed25519'
}
$PrivateKeyPath = Resolve-FullPath -Path $PrivateKeyPath
$serverScriptPath = Join-Path $PSScriptRoot 'ipms-ubuntu-hardening.sh'

foreach ($commandName in @('ssh', 'scp', 'ssh-keygen')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $commandName"
    }
}
foreach ($path in @($PrivateKeyPath, $serverScriptPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file not found: $path"
    }
}

if ($env:OS -eq 'Windows_NT') {
    $aclRepairScript = Join-Path $PSScriptRoot 'repair-alice-private-key-acl.ps1'
    & $aclRepairScript -PrivateKeyPath $PrivateKeyPath -Confirm:$false
}

$knownHostsCandidatePath = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("ipms-known-hosts-{0}" -f [Guid]::NewGuid().ToString('N'))
$normalizedScriptPath = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("ipms-hardening-{0}.sh" -f [Guid]::NewGuid().ToString('N'))
$remoteScriptPath = "/tmp/ipms-hardening-{0}.sh" -f [Guid]::NewGuid().ToString('N')

try {
    $probeStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $probeStartInfo.FileName = (Get-Command 'ssh').Source
    $probeStartInfo.Arguments = (
        '-p {0} -o UserKnownHostsFile="{1}" -o StrictHostKeyChecking=accept-new ' +
        '-o BatchMode=yes -o PreferredAuthentications=none ' +
        '-o PubkeyAuthentication=no -o PasswordAuthentication=no ' +
        '-o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no ' +
        '-o ConnectTimeout=10 -o ConnectionAttempts=1 -o LogLevel=ERROR ' +
        'host-key-probe@{2} exit'
    ) -f $Port, $knownHostsCandidatePath, $HostName
    $probeStartInfo.UseShellExecute = $false
    $probeStartInfo.CreateNoWindow = $true
    $probeStartInfo.RedirectStandardOutput = $true
    $probeStartInfo.RedirectStandardError = $true

    $probeProcess = [System.Diagnostics.Process]::new()
    $probeProcess.StartInfo = $probeStartInfo
    $null = $probeProcess.Start()
    $null = $probeProcess.StandardOutput.ReadToEnd()
    $probeError = $probeProcess.StandardError.ReadToEnd()
    $probeProcess.WaitForExit()
    $probeProcess.Dispose()

    if (-not (Test-Path -LiteralPath $knownHostsCandidatePath -PathType Leaf)) {
        throw "Unable to retrieve the SSH host key. $($probeError.Trim())"
    }

    $scanText = (Get-Content -LiteralPath $knownHostsCandidatePath -Raw) -replace
        "`r`n", "`n"
    if ($scanText -notmatch '(?m)^[^#\r\n]+\s+ssh-ed25519\s+') {
        throw 'The server did not provide an Ed25519 SSH host key.'
    }
    $fingerprintOutput = $scanText | & ssh-keygen -lf - -E sha256
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to calculate the SSH host-key fingerprint.'
    }
    $observedFingerprints = @(
        $fingerprintOutput | ForEach-Object {
            if ($_ -match 'SHA256:[A-Za-z0-9+/]+={0,2}') { $Matches[0] }
        }
    )
    if ($ExpectedHostKeyFingerprint -notin $observedFingerprints) {
        throw 'SSH host-key verification failed. Verify the fingerprint at the console.'
    }

    $commonSshArguments = @(
        '-p', $Port.ToString(),
        '-i', $PrivateKeyPath,
        '-o', "UserKnownHostsFile=$knownHostsCandidatePath",
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'ConnectionAttempts=1'
    )
    $target = "$AdminUser@$HostName"

    $preflightCommand = 'test "$(id -un)" = "{0}" && sudo -n true' -f $AdminUser
    $null = Invoke-CheckedNative -Command 'ssh' -Arguments (
        $commonSshArguments + @($target, $preflightCommand)
    ) -FailureMessage 'Pre-hardening SSH and sudo validation failed.'

    $scriptText = (Get-Content -LiteralPath $serverScriptPath -Raw) -replace
        "`r`n", "`n"
    [System.IO.File]::WriteAllText(
        $normalizedScriptPath,
        $scriptText,
        [System.Text.UTF8Encoding]::new($false)
    )

    if (-not $PSCmdlet.ShouldProcess(
        "$HostName`:$Port",
        'Apply the rollback-protected Ubuntu Appliance hardening baseline'
    )) {
        return
    }

    $scpArguments = @(
        '-P', $Port.ToString(),
        '-i', $PrivateKeyPath,
        '-o', "UserKnownHostsFile=$knownHostsCandidatePath",
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        $normalizedScriptPath,
        "${target}:$remoteScriptPath"
    )
    $null = Invoke-CheckedNative -Command 'scp' -Arguments $scpArguments `
        -FailureMessage 'Unable to stage the hardening program.'

    $remoteOptions = @(
        '--management-source', $ManagementSource,
        '--admin-user', $AdminUser,
        '--profile', $Profile,
        '--data-mount', $DataMount,
        '--rollback-minutes', $RollbackMinutes.ToString()
    )
    if ($SkipPackageUpdate) {
        $remoteOptions += '--skip-package-update'
    }

    $quotedOptions = $remoteOptions | ForEach-Object { "'$($_)'" }
    $applyCommand = "sudo -n bash '$remoteScriptPath' apply $($quotedOptions -join ' ')"
    $applyOutput = Invoke-CheckedNative -Command 'ssh' -Arguments (
        $commonSshArguments + @($target, $applyCommand)
    ) -FailureMessage (
        'Hardening failed. If access policy changed, the automatic rollback ' +
        "remains armed for $RollbackMinutes minutes."
    )
    $applyOutput | ForEach-Object { Write-Host $_ }

    $runLine = $applyOutput | Where-Object { $_ -match '^RUN_ID=' } |
        Select-Object -Last 1
    if (-not $runLine) {
        throw 'The hardening program did not return a rollback run identifier.'
    }
    $runId = ($runLine -replace '^RUN_ID=', '').Trim()
    if ($runId -notmatch '^[0-9]{8}T[0-9]{6}Z-[0-9]+$') {
        throw 'The hardening program returned an invalid rollback run identifier.'
    }

    $null = Invoke-CheckedNative -Command 'ssh' -Arguments (
        $commonSshArguments + @(
            $target,
            'test "$(id -un)" = "alice" && sudo -n true && test "$(sudo -n id -u)" = "0"'
        )
    ) -FailureMessage (
        'The independent post-change SSH session failed. Automatic rollback remains armed.'
    )

    Invoke-ExpectedSshFailure -Arguments (
        @('-p', $Port.ToString(),
            '-o', "UserKnownHostsFile=$knownHostsCandidatePath",
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'BatchMode=yes',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PasswordAuthentication=yes',
            "$AdminUser@$HostName", 'exit')
    ) -UnexpectedSuccessMessage 'Password SSH unexpectedly succeeded.'

    Invoke-ExpectedSshFailure -Arguments (
        $commonSshArguments + @("root@$HostName", 'exit')
    ) -UnexpectedSuccessMessage 'Direct root SSH unexpectedly succeeded.'

    $validateCommand = "sudo -n bash '$remoteScriptPath' validate $($quotedOptions -join ' ')"
    $validationOutput = Invoke-CheckedNative -Command 'ssh' -Arguments (
        $commonSshArguments + @($target, $validateCommand)
    ) -FailureMessage 'Effective hardening validation failed. Automatic rollback remains armed.'
    $validationOutput | ForEach-Object { Write-Host $_ }

    if ($ExerciseRollback) {
        $rollbackCommand = (
            'sudo -n /var/lib/ipms-bootstrap/hardening/{0}/rollback.sh; ' +
            'code=$?; sudo -n systemctl stop ' +
            'ipms-hardening-rollback-{0}.timer ' +
            'ipms-hardening-rollback-{0}.service 2>/dev/null || true; ' +
            'exit $code'
        ) -f $runId
        $null = Invoke-CheckedNative -Command 'ssh' -Arguments (
            $commonSshArguments + @($target, $rollbackCommand)
        ) -FailureMessage 'The explicit rollback exercise failed.'

        $postRollbackAccessCommand = (
            'test "$(id -un)" = "{0}" && sudo -n true && ' +
            'test "$(sudo -n id -u)" = "0"'
        ) -f $AdminUser
        $null = Invoke-CheckedNative -Command 'ssh' -Arguments (
            $commonSshArguments + @(
                $target,
                $postRollbackAccessCommand
            )
        ) -FailureMessage 'Independent SSH access failed after rollback.'

        $verifyRollbackCommand = (
            "sudo -n bash '$remoteScriptPath' verify-rollback " +
            "--run-id '$runId' --data-mount '$DataMount'"
        )
        $rollbackOutput = Invoke-CheckedNative -Command 'ssh' -Arguments (
            $commonSshArguments + @($target, $verifyRollbackCommand)
        ) -FailureMessage 'Rollback state verification failed.'
        $rollbackOutput | ForEach-Object { Write-Host $_ }
        Write-Host 'IPMS Ubuntu Appliance hardening rollback exercise passed.'
    }
    else {
        $commitCommand = (
            "sudo -n bash '$remoteScriptPath' commit --run-id '$runId'"
        )
        $commitOutput = Invoke-CheckedNative -Command 'ssh' -Arguments (
            $commonSshArguments + @($target, $commitCommand)
        ) -FailureMessage 'Validation passed, but the rollback timer could not be cancelled.'
        $commitOutput | ForEach-Object { Write-Host $_ }

        Write-Host 'IPMS Ubuntu Appliance hardening completed and committed successfully.'
    }
}
finally {
    if (
        (Test-Path -LiteralPath $knownHostsCandidatePath -PathType Leaf) -and
        (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)
    ) {
        $cleanupArguments = @(
            '-p', $Port.ToString(),
            '-i', $PrivateKeyPath,
            '-o', "UserKnownHostsFile=$knownHostsCandidatePath",
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes',
            "$AdminUser@$HostName",
            "rm -f -- '$remoteScriptPath'"
        )
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $null = & ssh @cleanupArguments 2>&1
        }
        catch {
            # The rollback path may temporarily make the host unreachable.
        }
        finally {
            $ErrorActionPreference = $previousPreference
        }
    }
    foreach ($path in @($knownHostsCandidatePath, $normalizedScriptPath)) {
        if (Test-Path -LiteralPath $path) {
            [System.IO.File]::Delete($path)
        }
    }
}
