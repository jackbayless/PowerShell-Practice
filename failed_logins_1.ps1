<#
My attempt at recreating that last script without ai 

Set critera
 - 3 failed logins, nomral alert (within 30)
 - login after hours, normal alert
 - 3 failed logins and then login, ultra alert
get your info
 - get win events, security, hash table, filter, xml
filter/logic on info
#>

$Days_to_scan = 7
$Events_to_scan = 100000

$LoginEvents = Get-WinEvent -FilterHashtable @{

    LogName = 'Security'; 
    ID = 4624,4625;
    StartTime = (Get-Date).AddDays(-$Days_to_scan)} -ErrorAction SilentlyContinue -MaxEvents $Events_to_scan
    | foreach-object {

        #gather xml data for each event, then reformat into cleaner object with only relevant fields
        $xmlData = @{}
        [xml]$log = $_.ToXml()
        
        foreach ($data in $log.Event.EventData.Data) {
            $xmlData[$data.Name] = $data.'#text'
        }

        [PSCustomObject]@{
            EventId = $_.Id
            Time = $_.TimeCreated
            Username = $xmlData['TargetUserName']
            IP = $xmlData['IpAddress']
            LogonType = $xmlData['LogonType']
            Domain = $xmlData['TargetDomainName']
        }

    }     
    | Where-object {-not ($_.EventId -eq 4624 -and $_.LogonType -eq 5)} #remove successful service logins
    | Sort-Object Time -Descending


    $Results = $LoginEvents | Where-Object {
        #check all successful logins for criteria
        ($_.EventId -eq 4624)
    } | foreach-object {

        $un = $_.Username
        $time = $_.Time

        #check for 3+ fails within 30 minutes
        $attempts = $LoginEvents | where-object {
            ($_.EventId -eq 4625) -and #failed login
            ($un -eq $_.Username) -and #username matches
            ($_.Time -ge $time.AddMinutes(-30)) -and #within 30 minutes of successful login
            ($_.Time -lt $time) #before successful login

        }

        #check for 3+ fails within 30 minutes before successful login
        $login_fails = $false
        if ($attempts.Count -ge 3) { 
            $login_fails = $true}

        #check for after hours login
        $after_hours = $false
        if ((($time.Hour -lt 8) -and ($time.Minute -lt 59)) -or (($time.Hour -gt 20) -and ($time.Minute -gt 0))) {
            $after_hours = $true }

        #assign alert type based on criteria
        if ($login_fails -and $after_hours) {
            $AltertType = 'ULTRA ALERT: Multiple Failed Logins and After Hours Login'
        } elseif ($login_fails) {
            $AltertType = 'Multiple Failed Logins'
        } elseif ($after_hours) {
            $AltertType = 'After Hours Login'
        } else {
            $AltertType = 'Normal Login'
        }

        if ($AltertType -ne 'Normal Login') {
        [PSCustomObject]@{
                Username = $_.Username
                Type = $AltertType
                Time = $_.Time
                IP = $_.IP
                FailedAttempts = $attempts.Count
                Domain = $_.Domain
                LogonType = $_.LogonType
            }
    }
}



    if ($Results.Count -eq 0) {
        Write-Host "No suspicious logins found."
    } else {
        $Results | Format-Table -AutoSize
    }


    $LoginEvents | Format-Table -AutoSize 
    $Results | Format-Table -AutoSize
    Write-Host $LoginEvents.Count "events scanned."