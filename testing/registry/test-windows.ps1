<#
.SYNOPSIS
    Test the Windows registry scanner against a cbom-lens build on real Windows.

.DESCRIPTION
    Mirrors the check-windows job in .github/workflows/check_pr.yml:
      1. Writes a self-signed PEM certificate to HKCU\Software\CBOMLensTest
      2. Runs cbom-lens with a registry-scan config pointed at that key
      3. Validates the JSON output is a CBOM with at least one component
      4. Cleans up the registry key

.PARAMETER Binary
    Path to the cbom-lens executable to test. Defaults to .\cbom-lens.exe.

.PARAMETER Keep
    Keep the generated config and output files after the run.

.EXAMPLE
    .\testing\registry\test-windows.ps1 -Binary .\cbom-lens-107.exe
#>

[CmdletBinding()]
param(
    [string]$Binary = ".\cbom-lens.exe",
    [switch]$Keep
)

$ErrorActionPreference = "Stop"

$RegKey = "HKCU:\Software\CBOMLensTest"
$ConfigFile = Join-Path $env:TEMP "cbom-lens-test.yaml"
$OutputFile = Join-Path $env:TEMP "cbom-lens-output.json"

function Cleanup {
    Write-Host "[*] Cleaning up..."
    Remove-Item -Path $RegKey -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $Keep) {
        Remove-Item -Path $ConfigFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $OutputFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "    Config kept at: $ConfigFile"
        Write-Host "    Output kept at: $OutputFile"
    }
}

try {
    if (-not (Test-Path $Binary)) {
        Write-Error "Binary not found: $Binary"
        exit 1
    }

    Write-Host "[*] Writing test registry values to $RegKey..."
    New-Item -Path $RegKey -Force | Out-Null
    $cert = New-SelfSignedCertificate -DnsName "cbom-lens-manual-test" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(1)
    $pem = "-----BEGIN CERTIFICATE-----`n"
    $pem += [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $pem += "`n-----END CERTIFICATE-----"
    Set-ItemProperty -Path $RegKey -Name "PEMCert" -Value $pem -Type String
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
    Write-Host "    -> $RegKey\PEMCert"

    Write-Host "[*] Writing config to $ConfigFile..."
    $config = @"
version: 0
service:
  mode: manual
registry:
  enabled: true
  paths:
    - hive: HKCU
      key: 'Software\CBOMLensTest'
"@
    $config | Out-File -FilePath $ConfigFile -Encoding utf8

    Write-Host "[*] Running registry scan via $Binary..."
    & $Binary run --config $ConfigFile | Out-File -FilePath $OutputFile -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cbom-lens exited with code $LASTEXITCODE"
        exit 1
    }

    Write-Host "[*] Validating output..."
    $json = Get-Content $OutputFile | ConvertFrom-Json
    if ($null -eq $json.bomFormat) {
        Write-Error "FAIL: output is not a valid CBOM (missing bomFormat)"
        Get-Content $OutputFile
        exit 1
    }
    $count = $json.components.Count
    Write-Host "    bomFormat:  $($json.bomFormat)"
    Write-Host "    components: $count"
    if ($count -eq 0) {
        Write-Error "FAIL: no components detected -- registry scanner may not be working"
        exit 1
    }
    Write-Host "PASS: registry scan produced $count component(s)."
}
finally {
    Cleanup
}
