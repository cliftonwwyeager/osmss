Param(
    [string]$BazaarUrl              = "https://bazaar.abuse.ch/export/csv/full/",
    [string]$LocalBazaarFile        = "bazaar.csv",
    [int]$BazaarHashIndex           = 1,
    [int]$BazaarSignatureIndex      = 7,
    [int]$BazaarVtPercentIndex      = 10,
    [string]$MalshareApiKey         = "YOUR_API_KEY_HERE",
    [string]$LocalMalshareFile      = "malshare.txt",
    [string]$MatchedFilesOutput     = "matched_files.csv",
    [Alias("d")][string[]]$Directories = @("C:\")
)

function Download-MalwareData {
    Param (
        [string]$Url,
        [string]$Destination
    )
    if (Test-Path $Destination) {
        $lastWrite = (Get-Item $Destination).LastWriteTime
        if ((Get-Date) - $lastWrite -lt [TimeSpan]::FromHours(24)) {
            Write-Host "Using cached data from $Destination" -ForegroundColor Green
            return $Destination
        }
    }
    Write-Host "Downloading data from $Url ..." -ForegroundColor Green
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
        if ($response.Headers.'Content-Disposition' -and ($response.Headers.'Content-Disposition' -match 'filename="?([^";]+)"?')) {
            $fileName = $matches[1]
            Write-Host "Detected filename from header: $fileName" -ForegroundColor Green
            $Destination = $fileName
        }
        $response.Content | Out-File -FilePath $Destination -Encoding ascii
        Write-Host "Download complete. Saved as $Destination" -ForegroundColor Green
        return $Destination
    }
    catch {
        Write-Error "Failed to download from $Url. Error: $($_.Exception.Message)"
        throw
    }
}

function Load-AllSignatures {
    Param (
        [string]$BazaarCsvPath,
        [int]$BazaarHashIndex,
        [int]$BazaarSignatureIndex,
        [int]$BazaarVtPercentIndex,
        [string]$MalsharePath
    )
    $signatures = @{}

    Write-Host "Loading signatures from MalwareBazaar (CSV)..." -ForegroundColor Green
    if (Test-Path $BazaarCsvPath) {
        try {
            $csvLines = Get-Content $BazaarCsvPath -ErrorAction Stop | Select-Object -Skip 1
            foreach ($line in $csvLines) {
                $row = $line -split ","
                if ($row.Count -gt $BazaarHashIndex) {
                    $hashVal = $row[$BazaarHashIndex].Trim('"')
                    if (-not [string]::IsNullOrWhiteSpace($hashVal)) {
                        $signature = if ($row.Count -gt $BazaarSignatureIndex) { $row[$BazaarSignatureIndex].Trim('"') } else { "Unknown" }
                        $vtPercent = if ($row.Count -gt $BazaarVtPercentIndex) { $row[$BazaarVtPercentIndex].Trim('"') } else { "Unknown" }
                        $signatures[$hashVal.ToLower()] = [pscustomobject]@{
                            Signature = $signature
                            VTPercent = $vtPercent
                        }
                    }
                }
            }
        }
        catch {
            Write-Error "Error processing $($BazaarCsvPath): $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "$BazaarCsvPath not found."
    }

    Write-Host "Loading signatures from Malshare (plain text)..." -ForegroundColor Green
    if (Test-Path $MalsharePath) {
        try {
            $lines = Get-Content $MalsharePath -ErrorAction Stop
            foreach ($line in $lines) {
                $hashVal = $line.Trim()
                if (-not [string]::IsNullOrWhiteSpace($hashVal)) {
                    if (-not $signatures.ContainsKey($hashVal.ToLower())) {
                        $signatures[$hashVal.ToLower()] = [pscustomobject]@{
                            Signature = "Unknown"
                            VTPercent = "Unknown"
                        }
                    }
                }
            }
        }
        catch {
            Write-Error "Error reading ${MalsharePath}: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "$MalsharePath not found."
    }
    Write-Host "Total combined signatures: $($signatures.Count)" -ForegroundColor Green
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
            $read = $fileStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $sha256.TransformBlock($buffer, 0, $read, $buffer, 0) | Out-Null
        }
        $sha256.TransformFinalBlock($buffer, 0, 0) | Out-Null
        ($sha256.Hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
    }
    catch {
        Write-Verbose "Cannot read file ${FilePath}: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($fileStream) {
            $fileStream.Close()
            $fileStream.Dispose()
        }
    }
}

Write-Host "`n==== OSMSS v1.0.8 ====" -ForegroundColor Green
$BazaarFile = Download-MalwareData -Url $BazaarUrl -Destination $LocalBazaarFile
Download-MalwareData -Url ("https://malshare.com/api.php?api_key=$MalshareApiKey&action=getlist") -Destination $LocalMalshareFile

$maliciousSignatures = Load-AllSignatures `
    -BazaarCsvPath $BazaarFile `
    -BazaarHashIndex $BazaarHashIndex `
    -BazaarSignatureIndex $BazaarSignatureIndex `
    -BazaarVtPercentIndex $BazaarVtPercentIndex `
    -MalsharePath $LocalMalshareFile

Write-Host "`nEnumerating files in directories: $($Directories -join ', ')" -ForegroundColor Green
try {
    $allFiles = Get-ChildItem -Path $Directories -Recurse -File -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Error enumerating files. (Try running as Administrator.)"
    return
}

$total = $allFiles.Count
Write-Host "Total files found: $total" -ForegroundColor Green

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "Using parallel scanning with progress bar..." -ForegroundColor Green
    $global:processed = 0
    $matches = foreach ($result in $allFiles | ForEach-Object -Parallel {
        $hashVal = Compute-Hash -FilePath $_.FullName
        $obj = [PSCustomObject]@{ Match = $null }
        if ($hashVal) {
            $hashVal = $hashVal.ToLower()
            $localSignatures = $using:maliciousSignatures
            if ($localSignatures.ContainsKey($hashVal)) {
                $malInfo = $localSignatures[$hashVal]
                $obj.Match = [PSCustomObject]@{
                    File       = $_.FullName
                    Signature  = $malInfo.Signature
                    VTPercent  = $malInfo.VTPercent
                }
            }
        }
        $obj
    } -ThrottleLimit ([Environment]::ProcessorCount)) {
        $global:processed++
        Write-Progress -Activity "Scanning files" -Status "Processed $global:processed of $total" -PercentComplete (($global:processed / $total) * 100)
        if ($result.Match) {
            $result.Match
        }
    }
} else {
    Write-Host "Scanning files sequentially with progress bar..." -ForegroundColor Green
    $matches = New-Object System.Collections.Generic.List[PSObject]
    $index = 0
    foreach ($file in $allFiles) {
        $index++
        Write-Progress -Activity "Scanning files" -Status "Computing hash for $($file.FullName)" -PercentComplete (($index / $total) * 100)
        $hashVal = Compute-Hash -FilePath $file.FullName
        if ($hashVal) {
            $hashVal = $hashVal.ToLower()
            if ($maliciousSignatures.ContainsKey($hashVal)) {
                $malInfo = $maliciousSignatures[$hashVal]
                $matches.Add([PSCustomObject]@{
                    File       = $file.FullName
                    Signature  = $malInfo.Signature
                    VTPercent  = $malInfo.VTPercent
                })
            }
        }
    }
}

Write-Host "`nScan complete. Found $($matches.Count) suspicious/malicious files." -ForegroundColor Green
Write-Host "Writing matches to $MatchedFilesOutput ..." -ForegroundColor Green
$matches | Export-Csv -Path $MatchedFilesOutput -NoTypeInformation
Write-Host "Done! Output written to $MatchedFilesOutput" -ForegroundColor Green
