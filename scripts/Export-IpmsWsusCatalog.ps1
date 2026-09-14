<#
.SYNOPSIS
Export an explicit WSUS update selection for the IPMS catalog-only pilot.
.DESCRIPTION
Reads the latest exact revision of each supplied update GUID through the WSUS
reporting API, exports a complete bounded metadata selection without computer
reports, and optionally posts it to the configured IPMS source. This does not
change WSUS approvals, download content, register clients or run Agent actions.
.NOTES
File Name     : Export-IpmsWsusCatalog.ps1
Version       : v0.2.0
Created       : 2026-09-13
Last Modified : 2026-09-13
Author        : Alice Endelgard
Organization  : Alvestrasza Corporation
Requires the Microsoft.UpdateServices.Administration assembly on Windows.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WsusServer,
    [ValidateRange(1, 65535)][int]$WsusPort = 8531,
    [bool]$WsusUseSsl = $true,
    [Parameter(Mandatory)][ValidateCount(1, 1000)][Guid[]]$UpdateId,
    [Parameter(Mandatory)][ValidateLength(1, 255)][string]$Scope,
    [Parameter(Mandatory)][string]$OutputPath,
    [Uri]$ReceptionUri,
    [string]$TokenFile
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ($Scope.Trim().Length -eq 0 -or @($UpdateId | Select-Object -Unique).Count -ne $UpdateId.Count) {
        throw 'Invalid catalog selection.'
    }
    if (Test-Path -LiteralPath $OutputPath) {
        throw 'The output file already exists; preserve it for retry.'
    }
    if (($null -ne $ReceptionUri) -ne (-not [string]::IsNullOrWhiteSpace($TokenFile))) {
        throw 'ReceptionUri and TokenFile must be supplied together.'
    }
    if ($null -ne $ReceptionUri -and (
        $ReceptionUri.Scheme -ne 'https' -or $ReceptionUri.UserInfo -or
        $ReceptionUri.Query -or $ReceptionUri.Fragment -or
        $ReceptionUri.AbsolutePath -notmatch '^/api/v1/update-sources/[0-9a-fA-F-]{36}/snapshots/$'
    )) {
        throw 'A fixed HTTPS reception endpoint is required.'
    }
    Add-Type -AssemblyName Microsoft.UpdateServices.Administration
    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer, $WsusUseSsl, $WsusPort)
    $wsus.PreferredCulture = 'en'
    $catalog = [System.Collections.Generic.List[object]]::new()
    foreach ($identity in $UpdateId) {
        # Revision zero requests latest; serialize the actual returned revision.
        $revision = [Microsoft.UpdateServices.Administration.UpdateRevisionId]::new($identity, 0)
        $update = $wsus.GetUpdate($revision)
        if ($null -eq $update -or $update.Id.UpdateId -ne $identity -or $update.Id.RevisionNumber -lt 1) {
            throw 'Update revision could not be resolved.'
        }
        $kb = @($update.KnowledgebaseArticles | ForEach-Object { [string]$_ })
        $products = @($update.ProductTitles | ForEach-Object { [string]$_ })
        if ([string]::IsNullOrWhiteSpace($update.Title) -or $update.Title.Length -gt 512 -or
            $kb.Count -gt 20 -or $products.Count -gt 20 -or
            @($kb | Where-Object { $_ -notmatch '^[0-9]{1,12}$' }).Count -gt 0 -or
            @($products | Where-Object { $_.Length -gt 128 -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
            ([string]$update.UpdateClassificationTitle).Length -gt 128 -or
            $update.MsrcSeverity.ToString().Length -gt 32) {
            throw 'Update metadata exceeds the reception contract.'
        }
        $catalog.Add([ordered]@{
            update_id = $update.Id.UpdateId.ToString('D')
            revision = [int]$update.Id.RevisionNumber
            title = [string]$update.Title
            kb_articles = $kb
            products = $products
            classification = [string]$update.UpdateClassificationTitle
            severity = $update.MsrcSeverity.ToString()
        })
    }
    $document = [ordered]@{
        schema_version = 1
        snapshot_id = [Guid]::NewGuid().ToString('D')
        observed_at = [DateTime]::UtcNow.ToString('o')
        complete = $true
        scope = $Scope.Trim()
        updates = @($catalog.ToArray())
        computers = @()
    }
    $json = ConvertTo-Json -InputObject $document -Depth 8 -Compress
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    if ($bytes.Length -gt 1048576) { throw 'Catalog exceeds the complete snapshot size limit.' }
    $stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    Write-Output "Catalog exported: $($catalog.Count) update revisions; no computer reports."

    if ($null -ne $ReceptionUri) {
        Add-Type -AssemblyName System.Net.Http
        $token = [System.IO.File]::ReadAllText($TokenFile).Trim()
        if ($token.Length -gt 128 -or $token -notmatch '^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$') {
            throw 'Invalid reception credential file.'
        }
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $body = [System.Net.Http.ByteArrayContent]::new($bytes)
        $body.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
        try {
            $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
            $response = $client.PostAsync($ReceptionUri, $body).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -notin @(200, 201)) {
                    throw 'IPMS did not accept the snapshot; preserve the exported file.'
                }
                Write-Output 'IPMS accepted the snapshot.'
            } finally { $response.Dispose() }
        } finally {
            $token = $null
            $body.Dispose()
            $client.Dispose()
        }
    }
} catch {
    # Provider/HTTP exception strings may contain endpoint or credential context.
    Write-Error 'WSUS catalog export or delivery failed. No server update action was performed. Preserve any completed output file and retry that exact snapshot after diagnosis.'
    exit 1
}
