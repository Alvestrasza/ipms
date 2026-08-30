[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$PrivateKeyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
    $PrivateKeyPath = Join-Path $PSScriptRoot '..\.ssh\alice_ipms_ed25519'
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This ACL repair is only supported on Windows.'
}

$PrivateKeyPath = [System.IO.Path]::GetFullPath($PrivateKeyPath)
$PublicKeyPath = "$PrivateKeyPath.pub"

foreach ($path in @($PrivateKeyPath, $PublicKeyPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required key file not found: $path"
    }
}

foreach ($commandName in @('icacls', 'ssh-keygen')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $commandName"
    }
}

$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$identityName = $windowsIdentity.Name
$identitySid = $windowsIdentity.User.Value
$existingAcl = Get-Acl -LiteralPath $PrivateKeyPath
$existingOwnerSid = (
    New-Object System.Security.Principal.NTAccount($existingAcl.Owner)
).Translate([System.Security.Principal.SecurityIdentifier]).Value

$unexpectedAllowRules = @(
    $existingAcl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value -ne $identitySid
    }
)

if ($existingOwnerSid -eq $identitySid -and $unexpectedAllowRules.Count -eq 0) {
    Write-Output "Private key ACL is already restricted to $identityName."
    return
}

if (-not $PSCmdlet.ShouldProcess(
    $PrivateKeyPath,
    "Re-home the private key and restrict access to $identityName"
)) {
    return
}

$suffix = [Guid]::NewGuid().ToString('N')
$temporaryPath = "$PrivateKeyPath.acl-repair.$suffix"
$backupPath = "$PrivateKeyPath.acl-backup.$suffix"
$backupCreated = $false
$replacementInstalled = $false

try {
    $keyBytes = [System.IO.File]::ReadAllBytes($PrivateKeyPath)
    [System.IO.File]::WriteAllBytes($temporaryPath, $keyBytes)

    & icacls.exe $temporaryPath /inheritance:r /grant:r "${identityName}:(F)" |
        Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to restrict the replacement private-key ACL.'
    }

    $temporaryAcl = Get-Acl -LiteralPath $temporaryPath
    $temporaryOwnerSid = (
        New-Object System.Security.Principal.NTAccount($temporaryAcl.Owner)
    ).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $temporaryUnexpectedRules = @(
        $temporaryAcl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value -ne $identitySid
        }
    )

    if (
        $temporaryOwnerSid -ne $identitySid -or
        $temporaryUnexpectedRules.Count -ne 0
    ) {
        throw 'The replacement private-key ACL is not sufficiently restricted.'
    }

    $expectedPublicKey = (
        (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim() -split '\s+'
    )[0..1] -join ' '
    $derivedPublicKey = (
        ((& ssh-keygen -y -f $temporaryPath).Trim() -split '\s+')[0..1]
    ) -join ' '
    if ($LASTEXITCODE -ne 0 -or $derivedPublicKey -ne $expectedPublicKey) {
        throw 'The replacement private key does not match the public key.'
    }

    Move-Item -LiteralPath $PrivateKeyPath -Destination $backupPath
    $backupCreated = $true
    Move-Item -LiteralPath $temporaryPath -Destination $PrivateKeyPath
    $replacementInstalled = $true

    $finalPublicKey = (
        ((& ssh-keygen -y -f $PrivateKeyPath).Trim() -split '\s+')[0..1]
    ) -join ' '
    if ($LASTEXITCODE -ne 0 -or $finalPublicKey -ne $expectedPublicKey) {
        throw 'Final validation of the repaired private key failed.'
    }

    Remove-Item -LiteralPath $backupPath -Force
    $backupCreated = $false
    Write-Output "Private key ACL is now restricted to $identityName."
}
catch {
    if ($replacementInstalled -and (Test-Path -LiteralPath $PrivateKeyPath)) {
        Remove-Item -LiteralPath $PrivateKeyPath -Force
        $replacementInstalled = $false
    }

    if ($backupCreated -and (Test-Path -LiteralPath $backupPath)) {
        Move-Item -LiteralPath $backupPath -Destination $PrivateKeyPath
        $backupCreated = $false
    }

    throw
}
finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
