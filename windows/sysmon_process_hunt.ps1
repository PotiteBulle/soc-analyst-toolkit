<#
.SYNOPSIS
  Hunt Sysmon Event ID 1 sur des commandes d'administration ou reconnaissance.
#>
[CmdletBinding()]
param(
    [int]$MaxEvents = 500,
    [string]$OutputCsv = ".\sysmon-process-hunt.csv"
)

$logName = "Microsoft-Windows-Sysmon/Operational"
$patterns = "whoami.exe|hostname.exe|ipconfig.exe|tasklist.exe|net.exe|nltest.exe|cmd.exe|powershell.exe|pwsh.exe|rundll32.exe|regsvr32.exe|mshta.exe|certutil.exe|bitsadmin.exe"

Write-Host "[+] Recherche Sysmon Event ID 1" -ForegroundColor Cyan

$events = Get-WinEvent -FilterHashtable @{LogName=$logName; Id=1} -MaxEvents $MaxEvents -ErrorAction Stop

$rows = foreach ($event in $events) {
    $msg = $event.Message
    if ($msg -match $patterns) {
        [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventId     = $event.Id
            Computer    = $event.MachineName
            Image       = (($msg -split "`n") | Where-Object { $_ -like "Image:*" }) -replace '^Image:\s*',''
            CommandLine = (($msg -split "`n") | Where-Object { $_ -like "CommandLine:*" }) -replace '^CommandLine:\s*',''
            User        = (($msg -split "`n") | Where-Object { $_ -like "User:*" }) -replace '^User:\s*',''
        }
    }
}

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsv
Write-Host "[+] Export CSV : $OutputCsv" -ForegroundColor Green
