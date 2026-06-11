<#

get failed logins, make a report

Suspicous:
After 10pm or before 8am
3+ fails within 30minutes
3+ fails then login - alert!!!

#
#>

<# Attempt 1 below, pretty sad but not with chat gpt

$Days_Scanned = 30

Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id=4624, 4625; StartTime = (Get-Date).AddDays(-($Days_Scanned))} |
    Select-Object TimeCreated, Id, Message -First 20


    #>

$DaysToScan = 7

## get events
$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = (Get-Date).AddDays(-($DaysToScan))

} | Where-Object { # filter for after 12 or before 8
    ($_.timeCreated -ge 22) -or ($_.TimeCreated -le 8)

} | ForEach-Object { # grab xml data for more precise data
    [xml]$xml = $_.ToXml() #[xml] -> cast var into xml type

    #create empty hashtable to store data
    $data = @{}
    
    #put every xml data type as key and put actual data as value
    #IP address -> 192.168.0.0
    #Domain -> AAA
    #logon type -> 2
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text' #how to actually access text of xml
    }

    #create cleaner object with only fields that are relevant
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventId = $_.Id
        UserName = $data['TargetUserName']
        Domain = $data['TargetDomainName']
        SourceIP = $data['IpAddress']
        LogonType = $data['LogonType']
    }

} | Where-Object { #filter out noise or service accounts
    $_.Username -and
    $_.Username -notmatch '\$$' -and
    $_.Username -notin @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -and
    $_.SourceIP -and
    $_.SourceIP -ne '-'
} | Sort-Object TimeCreated


<#
$Results = foreach ($Event in $Events) {
    $Time = $Event.TimeCreated
    $User = $Event.UserName
    $Domain = $Event.Domain
    $IP = $Event.SourceIP
    $LogonType = $Event.LogonType

    [PSCustomObject]@{
        TimeCreated = $Time
        UserName = "$User"
        SourceIP = $IP
        LogonType = $LogonType
    }
}
    #>


#loop through successful logins
$Results = foreach ($login in $Events | Where-Object { $_.EventId -eq 4624 }) {
    #search through events that match criteria
    $failsBeforeLogin = $Events | Where-Object {
        $_.EventId -eq 4625 -and
        $_.Username -eq $login.Username -and
        $_.SourceIP -eq $login.SourceIP -and
        $_.TimeCreated -lt $login.TimeCreated -and
        $TimeCreated -ge $login.TimeCreated.AddMinutes(-30)

    }

    #if multiple fails, create report object
    if ($failsBeforeLogin.Count -ge 3) {
        [PSCustomObject]@{
            username = $login.Username
            SourceIP = $login.SourceIP
            SuccessfulAt = $login.TimeCreated
            FailedCount = $failsBeforeLogin.Count
            FirstFailedAt = ($failsBeforeLogin | Select-Object -First 1).TimeCreated
            LastFailedAt = ($failsBeforeLogin | Select-Object -Last 1).TimeCreated
            LogonType = $login.LogonType
        }
    }
}

if ($Results.count -eq 0) {
    Write-Host "No suspcious logins found"
} else {
    Write-Host "Suspicious Logins:"
    $Results | Format-Table
}
Write-Host
Write-Host
Write-Host
Write-Host "Events:"
$Events | Format-Table

