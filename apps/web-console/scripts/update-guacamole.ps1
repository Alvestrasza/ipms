[CmdletBinding()]
param([string]$ArtifactDirectory)
$ErrorActionPreference = 'Stop'
$artifactName = 'guacamole-common-js-1.6.0.zip'
$sources = @{
    $artifactName = @('https://repo.maven.apache.org/maven2/org/apache/guacamole/guacamole-common-js/1.6.0/guacamole-common-js-1.6.0.zip', '228c08dd0b3e860bcbae1dbccfdcbe55652bebed2aec4c59b738ee025d1354d1e35983459bf25c57495c733d6502ec1e469e9bcb596235a3eac96b62345e1bac')
    'LICENSE' = @('https://raw.githubusercontent.com/apache/guacamole-client/1.6.0/LICENSE', 'e7b34e86f00df8bd4f4285b383c969b5d381ea8e3d2381919af9a4095c0c3984087ba833ffd343b29fb65ba6d3b55938d4b078aa8da444e062afec5fa2777144')
    'NOTICE' = @('https://raw.githubusercontent.com/apache/guacamole-client/1.6.0/NOTICE', '63f48417c420477a2b86c1b3a8657a9eb028b708e3ae2f128096bb0c900e830182dbc551c816517c039bb236c7487e9a38e15cdc7f2f17f8dad95e74473ad383')
}
if (-not $ArtifactDirectory) {
    $ArtifactDirectory = Join-Path ([IO.Path]::GetTempPath()) ('ipms-guacamole-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $ArtifactDirectory | Out-Null
    foreach ($name in $sources.Keys) {
        Invoke-WebRequest -Uri $sources[$name][0] -OutFile (Join-Path $ArtifactDirectory $name)
    }
}
foreach ($name in $sources.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $ArtifactDirectory $name) -Algorithm SHA512).Hash -ne $sources[$name][1]) {
        throw "Pinned artifact digest mismatch: $name"
    }
}
$destination = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../public/vendor/guacamole/1.6.0'))
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $ArtifactDirectory $artifactName))
try {
    $entry = $archive.GetEntry('guacamole-common-js/all.min.js')
    if (-not $entry -or $entry.Length -ne 78778) { throw 'Unexpected browser artifact layout.' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $destination 'all.min.js'), $true)
} finally { $archive.Dispose() }
foreach ($name in @('LICENSE', 'NOTICE')) {
    Copy-Item -LiteralPath (Join-Path $ArtifactDirectory $name) -Destination (Join-Path $destination $name) -Force
}
Write-Output 'Verified Guacamole 1.6.0 browser artifact and license notices extracted.'
