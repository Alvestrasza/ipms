[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServiceName = 'IPMS Agent'
)

$ErrorActionPreference = 'Stop'
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Verbose "The service '$ServiceName' is not installed."
    return
}

if ($service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop service')) {
    Stop-Service -Name $ServiceName -ErrorAction Stop
}
if ($PSCmdlet.ShouldProcess($ServiceName, 'Delete service registration')) {
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
}
