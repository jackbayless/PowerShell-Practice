<#
Do file intergrity checks and make a baseline for system 32, startup and user profile folders, and registy keys
#>

param (
    [Parameter(Mandatory = $true)]
    [string] $StartingPath,

    [ValidateSet("Baseline", "Check")]
    [string] $Mode = "Check"

)


# set paths and make baselines

$BaselineLocalPath = ".\files\baseline.csv"
$BaselineFullPath = (Resolve-Path $BaselineLocalPath)
$hash_alg = 'SHA256'

Write-Host 'Baseline File Path: ' $BaselineFullPath -ForegroundColor Green


if (-not (Test-Path -Path $BaselineLocalPath)) {
    New-Item -Path $BaselineLocalPath -ItemType File -Force | Out-Null
}

$BaselineMap = @{}
get-content $BaselineLocalPath | ConvertFrom-Csv | ForEach-Object {
    $BaselineMap[$_.Path] = $_.Hash
}



# make the baseline file

if ($Mode -eq "Baseline" -or $BaselineMap.Count -eq 0) {
    if ($BaselineMap.Count -eq 0) {Write-Host "No baseline data found. Creating new baseline..." -ForegroundColor Yellow}

    get-childitem -Path $StartingPath -Recurse -ErrorAction SilentlyContinue |
    where-object { $_.FullName -ne $BaselineFullPath} |
    foreach-object {
        $file = $_
        if ($file.PSIsContainer -eq $false) {
        $hash = Get-FileHash -Path $file.FullName -Algorithm $hash_alg
        [PSCustomObject]@{
            Path = $file.FullName
            Hash = $hash.Hash
        }
    } 

} | 
Export-Csv -Path $BaselineLocalPath -NoTypeInformation
write-host 'Baseline Created' -ForegroundColor Green
exit
}


# check the baseline file

$FailedFiles = @{}

$CurrentFiles = get-childitem -Path $StartingPath -Recurse -ErrorAction SilentlyContinue |
where-object { $_.FullName -ne $BaselineFullPath}

foreach ($file in $CurrentFiles) {
    $name = $file.FullName
    $hash = get-FileHash $name -Algorithm $hash_alg

    if (-not ($BaselineMap[$name] -eq $hash.Hash)) {
        $FailedFiles[$name] = $hash
    }
}

if ($FailedFiles.Count -ne 0) {
    Write-Host "FILE INTEGRITY FAILED FOR THESE FILES:" -ForegroundColor Red
    $FailedFiles.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Path            = Resolve-Path -Path $_.Value.Path -Relative
            Hash            = $_.Value.Hash
            'Previous Hash' = $BaselineMap[$_.Name]
        }
    } | 
    Format-Table -AutoSize
    exit
}

Write-Host "All files pass`n" -ForegroundColor Green

