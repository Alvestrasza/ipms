[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$BootstrapUser,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^SHA256:[A-Za-z0-9+/]{40,44}={0,2}$')]
    [string]$ExpectedHostKeyFingerprint,

    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [string]$PrivateKeyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
    $PrivateKeyPath = Join-Path $PSScriptRoot '..\.ssh\alice_ipms_ed25519'
}

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

$PrivateKeyPath = Resolve-FullPath -Path $PrivateKeyPath
$PublicKeyPath = "$PrivateKeyPath.pub"
$SshDirectory = Split-Path -Parent $PrivateKeyPath
$KnownHostsPath = Join-Path $SshDirectory 'known_hosts'

foreach ($commandName in @('ssh', 'ssh-keygen')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $commandName"
    }
}

if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
    throw "Private key not found: $PrivateKeyPath"
}

if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
    throw "Public key not found: $PublicKeyPath"
}

$publicKey = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,3}(?: .*)?$') {
    throw 'The public key is not a valid OpenSSH Ed25519 public key.'
}

$knownHostsCandidatePath = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("ipms-known-hosts-{0}" -f [Guid]::NewGuid().ToString('N'))

$probeStartInfo = New-Object System.Diagnostics.ProcessStartInfo
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

$probeProcess = New-Object System.Diagnostics.Process
$probeProcess.StartInfo = $probeStartInfo

try {
    $null = $probeProcess.Start()
    $null = $probeProcess.StandardOutput.ReadToEnd()
    $probeError = $probeProcess.StandardError.ReadToEnd()
    $probeProcess.WaitForExit()
    $probeProcess.Dispose()

    if (-not (Test-Path -LiteralPath $knownHostsCandidatePath -PathType Leaf)) {
        throw (
            "Unable to retrieve the Ed25519 SSH host key from {0}:{1}. {2}" -f
                $HostName,
                $Port,
                $probeError.Trim()
        )
    }

    $scanText = (
        Get-Content -LiteralPath $knownHostsCandidatePath -Raw
    ) -replace "`r`n", "`n"
}
finally {
    if (Test-Path -LiteralPath $knownHostsCandidatePath) {
        [System.IO.File]::Delete($knownHostsCandidatePath)
    }
}

if ($scanText -notmatch '(?m)^[^#\r\n]+\s+ssh-ed25519\s+') {
    throw "The server did not provide an Ed25519 SSH host key."
}
$fingerprintOutput = $scanText | & ssh-keygen -lf - -E sha256
if ($LASTEXITCODE -ne 0 -or -not $fingerprintOutput) {
    throw 'Unable to calculate the SSH host key fingerprint.'
}

$observedFingerprints = @(
    $fingerprintOutput |
        ForEach-Object {
            if ($_ -match 'SHA256:[A-Za-z0-9+/]+={0,2}') {
                $Matches[0]
            }
        }
)

if ($ExpectedHostKeyFingerprint -notin $observedFingerprints) {
    throw (
        "SSH host key verification failed. Expected {0}; observed {1}. " +
        'Verify the fingerprint at the server console before retrying.'
    ) -f $ExpectedHostKeyFingerprint, ($observedFingerprints -join ', ')
}

Set-Content -LiteralPath $KnownHostsPath -Value $scanText -NoNewline -Encoding ascii

$publicKeyBase64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($publicKey)
)

$remoteScript = @'
set -euo pipefail

public_key_base64="$1"
expected_user="alice"
expected_home="/home/alice"

if id "$expected_user" >/dev/null 2>&1; then
    actual_uid="$(id -u "$expected_user")"
    actual_home="$(getent passwd "$expected_user" | cut -d: -f6)"
    if [ "$actual_uid" = "0" ] || [ "$actual_home" != "$expected_home" ]; then
        echo "Existing alice account has an unsafe or unexpected identity." >&2
        exit 1
    fi
else
    useradd --create-home --home-dir "$expected_home" --shell /bin/bash "$expected_user"
fi

passwd --lock "$expected_user" >/dev/null 2>&1 || true

install -d -m 0700 -o "$expected_user" -g "$expected_user" "$expected_home/.ssh"

public_key="$(printf '%s' "$public_key_base64" | base64 --decode)"
authorized_keys="$expected_home/.ssh/authorized_keys"
touch "$authorized_keys"
chown "$expected_user:$expected_user" "$authorized_keys"
chmod 0600 "$authorized_keys"

if ! grep -Fqx -- "$public_key" "$authorized_keys"; then
    printf '%s\n' "$public_key" >> "$authorized_keys"
fi

sudoers_target="/etc/sudoers.d/90-ipms-alice"
sudoers_temp="$(mktemp)"
trap 'rm -f "$sudoers_temp"' EXIT
printf '%s\n' 'alice ALL=(ALL:ALL) NOPASSWD: ALL' > "$sudoers_temp"
chmod 0440 "$sudoers_temp"
visudo -cf "$sudoers_temp" >/dev/null
install -o root -g root -m 0440 "$sudoers_temp" "$sudoers_target"
visudo -cf "$sudoers_target" >/dev/null

echo "alice SSH access and passwordless sudo configured successfully."
'@

$remoteScript = $remoteScript -replace "`r`n", "`n"
$remoteScriptBase64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($remoteScript)
)

$elevationCommand = if ($BootstrapUser -eq 'root') { 'bash' } else { 'sudo bash' }
$remoteCommand = (
    "printf '%s' '{0}' | base64 --decode | {1} -s -- '{2}'" -f
        $remoteScriptBase64,
        $elevationCommand,
        $publicKeyBase64
)

$sshCommonArguments = @(
    '-p', $Port.ToString(),
    '-o', "UserKnownHostsFile=$KnownHostsPath",
    '-o', 'StrictHostKeyChecking=yes'
)

$target = "$BootstrapUser@$HostName"
$action = 'Create or validate alice, install its public key, and grant passwordless sudo'

if (-not $PSCmdlet.ShouldProcess("$HostName`:$Port", $action)) {
    return
}

& ssh @sshCommonArguments -t -- $target $remoteCommand
if ($LASTEXITCODE -ne 0) {
    throw "Remote bootstrap failed with SSH exit code $LASTEXITCODE."
}

$verificationArguments = @(
    '-i', $PrivateKeyPath,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes'
) + $sshCommonArguments

$verificationCommand = @'
set -eu
test "$(id -un)" = "alice"
sudo -n true
test "$(sudo -n id -u)" = "0"
printf '%s\n' 'alice login and passwordless sudo verification succeeded.'
'@

& ssh @verificationArguments -- "alice@$HostName" $verificationCommand
if ($LASTEXITCODE -ne 0) {
    throw "alice verification failed with SSH exit code $LASTEXITCODE."
}
