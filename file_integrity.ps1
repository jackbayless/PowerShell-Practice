<#
Do file intergrity checks and make a baseline for system 32, startup and user profile folders, and registy keys
#>

param (
    [Parameter(Mandatory = $true)]
    [string] $StartingPath,

    [ValidateSet("Baseline", "Check")]
    [string] $Mode = "Check"

)

$BaselineFilePath = ".\files\baseline.csv"

if (-not (Test-Path -Path $BaselineFilePath)) {
    New-Item -Path $BaselineFilePath -ItemType File -Force | Out-Null
}

$BaselineData = get-content $BaselineFIlePath | ConvertFrom-Csv

if ($Mode -eq "Baseline" -or $BaselineData.Count -eq 0) {
    if ($BaselineData.Count -eq 0) {Write-Host "No baseline data found. Creating new baseline..." -ForegroundColor Yellow}

    get-childitem -Path $StartingPath -Recurse -ErrorAction SilentlyContinue | 
    foreach-object {
        $file = $_
        if ($file.PSIsContainer -eq $false) {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        [PSCustomObject]@{
            Path = $file.FullName
            Hash = $hash.Hash
        }
    } 

} | 
Export-Csv -Path $BaselineFilePath -NoTypeInformation
}




