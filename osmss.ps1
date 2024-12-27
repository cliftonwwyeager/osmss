Param(
    [string]$MalwareDataUrl        = "https://bazaar.abuse.ch/export/csv/full/",
    [string]$LocalCsvFile          = "full.csv",
    [string]$MatchedFilesOutput    = "matched_files.csv",
    [int]$MalwareHashColIndex      = 1,
    [int]$MalwareSignatureColIndex = 7,
    [int]$MalwareVtPercentColIndex = 10
)

function Download-MalwareData {
    Param (
        [string]$Url,
        [string]$Destination
    )

    Write-Host "Downloading malware data from $Url ..."
    try {
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $Destination
        Write-Host "Download complete. File saved as $Destination"
    }
    catch {
        Write-Error "Failed to download malware data from $Url. Error: $($_.Exception.Message)"
        throw
    }
}

function Load-MaliciousSignatures {
    Param (
        [string]$CsvPath,
        [int]$HashIndex,
        [int]$SignatureIndex,
        [int]$VtPercentIndex
    )

    Write-Host "Loading malicious signatures from $CsvPath ..."
    if (-not (Test-Path $CsvPath)) {
        Write-Error "$CsvPath not found. Please download the malware data first."
        throw
    }

    $signatures = @{}

    try {
        $csvLines = Get-Content $CsvPath -ErrorAction Stop
        $csvLines = $csvLines | Select-Object -Skip 1

        foreach ($line in $csvLines) {
            $row = $line -split ","
            if ($row.Count -gt $HashIndex) {
                $hashVal = $row[$HashIndex].Trim('"')
                if (-not [string]::IsNullOrWhiteSpace($hashVal)) {
                    $signature = if ($row.Count -gt $SignatureIndex) {
                        $row[$SignatureIndex].Trim('"')
                    } else {
                        "Unknown"
                    }
                    $vtPercent = if ($row.Count -gt $VtPercentIndex) {
                        $row[$VtPercentIndex].Trim('"')
                    } else {
                        "Unknown"
                    }
                    $signatures[$hashVal.ToLower()] = [pscustomobject]@{
                        Signature = $signature
                        VTPercent = $vtPercent
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error loading signatures: $($_.Exception.Message)"
        throw
    }

    Write-Host "Loaded $($signatures.Count) malicious signatures."
    return $signatures
}

function Compute-Hash {
    Param (
        [string]$FilePath
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fileStream = $null

    try {
        $fileStream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $buffer = New-Object byte[] 4096
        while ($true) {
            $read = $fileStream.Read($buffer, 0, 4096)
            if ($read -le 0) { break }
            $sha256.TransformBlock($buffer, 0, $read, $buffer, 0) | Out-Null
        }
        $sha256.TransformFinalBlock($buffer, 0, 0) | Out-Null
        ($sha256.Hash | ForEach-Object ToString x2) -join ""
    }
    catch {
        Write-Verbose "Cannot read file $($FilePath): $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($fileStream) {
            $fileStream.Close()
            $fileStream.Dispose()
        }
    }
}

Write-Host "`n==== OSMSS v1.0.7 (Console Version) ===="

Download-MalwareData -Url $MalwareDataUrl -Destination $LocalCsvFile

$maliciousSignatures = Load-MaliciousSignatures `
    -CsvPath $LocalCsvFile `
    -HashIndex $MalwareHashColIndex `
    -SignatureIndex $MalwareSignatureColIndex `
    -VtPercentIndex $MalwareVtPercentColIndex

Write-Host "`nEnumerating files on C:\ ..."
try {
    $allFiles = Get-ChildItem -Path "C:\" -Recurse -File -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Error enumerating files on C:\. (Try running as Administrator.)"
    return
}

Write-Host "Total files found: $($allFiles.Count)"

$matches = New-Object System.Collections.Generic.List[PSObject]

$index = 0
$total = $allFiles.Count

foreach ($file in $allFiles) {
    $index++
    Write-Progress -Activity "Scanning files" -Status "Computing hash for $($file.FullName)" -PercentComplete (($index / $total) * 100)
    $hashVal = Compute-Hash -FilePath $file.FullName
    if ($null -ne $hashVal) {
        $hashVal = $hashVal.ToLower()
        if ($maliciousSignatures.ContainsKey($hashVal)) {
            $malInfo = $maliciousSignatures[$hashVal]
            $matches.Add([pscustomobject]@{
                File       = $file.FullName
                Signature  = $malInfo.Signature
                VTPercent  = $malInfo.VTPercent
            })
        }
    }
}

Write-Host "`nScan complete. Found $($matches.Count) suspicious/malicious files."
Write-Host "Writing matches to $MatchedFilesOutput ..."
$matches | Export-Csv -Path $MatchedFilesOutput -NoTypeInformation
Write-Host "Done! Output written to $MatchedFilesOutput"