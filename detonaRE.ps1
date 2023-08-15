<#
detonaRE.ps1 v1.2
https://github.com/dwmetz/detonaRE
Author: @dwmetz

detonaRE - from the Latin, "to detonate"

Script Functions:

- initiates .etl packet capture
- initiates Process Monitor with a filter applied for the malware to be detonated
- launches malware sample
- terminates packet capture after specified interval
- initiates evidence collection with Magnet RESPONSE (memory, process, and triage capture)
- terminates the malware process
- converts collected .etl file to .pcap with etl2pcapng.
- converts collected .pml to .csv

Prerequisites:

> Magnet RESPONSE
> etl2pcapng.exe
> procmon.exe

## variable configuration example:
$malwspath = "E:" ## malware source path
$malwdpath = "C:\Users\REM\Desktop\Malware\" ## malware destination path
$malware = "redline-76ca4a.exe" ## malware executable
$pcaptime = 180 ## duration in seconds for pcap capture
$toolsdir = "E:\Tools" ## MagnetRESPONSE.exe and etl2pcapng.exe
$procmonconfig = "$toolsdir\redline.pmc" ## Process Monitor configuration
#>
param ([switch]$Elevated)
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Test-Admin) -eq $false)  {
    if ($elevated) {
    } else {
        Write-host -fore DarkCyan "
        Admin permissions not detected. Exiting.
        "        
    }
    exit
}
$version = "1.2"
[console]::ForegroundColor="Cyan"
## variable configuration:
$malwspath = "E:" ## malware source path
$malwdpath = "C:\Users\REM\Desktop\Malware\" ## malware destination path on target host
$malware = "malware.exe" ## malware executable
$pcaptime = 180 ## duration in seconds for pcap capture
$toolsdir = "E:\Tools" # tools directory
$collectiondir = "E:\Collections" ## output directory for collections
$procmonconfig = "$toolsdir\malw.pmc" ## Process Monitor configuration file
##
Clear-Host
Write-Host ""
Write-Host ""
Write-host "
                                                        
    #          #                          ####   ##### 
    #          #                          #   #  #     
 ## #   ###   ####    ###   # ##    ###   #   #  #     
#  ##  #   #   #     #   #  ##  #      #  ####   ####  
#   #  #####   #     #   #  #   #   ####  # #    #     
#  ##  #       #  #  #   #  #   #  #   #  #  #   #     
 ## #   ###     ##    ###   #   #   ####  #   #  #####                                                  
"
Write-host "
Capture. Detonate. Collect.
"
Write-Host "version $version | @dwmetz | $([char]0x00A9)2023 bakerstreetforensics.com"
Write-Host ""
Write-Host ""
Set-Location $malwspath
Copy-Item $malwspath\$malware $malwdpath
Set-Location $malwdpath
If (Test-Path -Path $collectiondir) {
    Write-Host " "
}
Else {
    $null = mkdir $collectiondir
    If (Test-Path -Path $collectiondir) {
        Write-Host " "
    }
    Else {
        Write-Host -For Cyan "Error creating directory."
    }
}
$tstamp = (Get-Date -Format "-yyyyMMddHHmm")
$collection = $env:computername+$tstamp
$malproc = [io.path]::GetFileNameWithoutExtension($malware)
If (Test-Path -Path $collectiondir\$collection) {
    Write-Host " "
}
Else {
    $null = mkdir $collectiondir\$collection
    If (Test-Path -Path $collectiondir\$collection) {
        Write-Host "Collection directory $collectiondir\$collection"
    }
    Else {
        Write-Host -For Cyan "Error creating directory."
    }
}
# PROCESS MONITOR
Set-Location $toolsdir
Write-host "
Initiating Process Monitor" -Fore yellow
.\Procmon.exe /accepteula /quiet /loadconfig $procmonconfig /backingfile $collectiondir\$collection\$collection-$malproc
Write-host "
Initiating PCAP collection" -Fore yellow
#Get the local IPv4 address
$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress
# Start 'pcap' capture
netsh trace start capture=yes IPv4.Address=$env:HostIP tracefile=$collectiondir\$collection\$collection.etl
Sleep 5
# Malware detonation
Write-host "
Detonating malware sample" -Fore yellow
Set-Location $malwdpath
Start-process -filepath $malware
# Packet capture timer
function Wait-Count($s){
    do {
        Write-Progress -SecondsRemaining $s -Activity "Malware running" -Status "Time left for packet capture " -Id 1
        $s--
        Start-Sleep -Seconds 1
    } until ($s -eq 0)
} 
Wait-Count $pcaptime
Set-Location $toolsdir
# Terminate Process Monitor Capture
Write-host "
Terminating Process Monitor" -Fore yellow
.\Procmon.exe /Terminate
Write-host "
Terminating packet capture" -Fore yellow
# Terminate .etl capture
netsh trace stop
# Magnet RESPONSE evidence triage collection
Write-host "
Initiating Magnet RESPONSE evidence collection" -Fore yellow
.\MagnetRESPONSE.exe /accepteula /unattended /output:$collectiondir\$collection /caseref:$collection /captureram /capturepagefile /capturevolatile /capturesystemfiles /captureextendedprocessinfo /saveprocfiles
Write-host "
[Collecting Evidence]"
Wait-Process -Name "MagnetRESPONSE"
# Terminate malware process
Write-host "
Terminating malware process" -Fore yellow
Get-process $malproc | stop-process
# Convert .etl to .pcap
Write-host "
Converting .etl file to .pcap" -Fore yellow
.\etl2pcapng.exe $collectiondir\$collection\$collection.etl $collectiondir\$collection\$collection.pcap
# Convert Process Monitor .pml to CSV
Write-host "
Converting Process Monitor PML to CSV" -Fore yellow
.\Procmon.exe /openlog $collectiondir\$collection\$collection-$malproc.pml /SaveApplyFilter /SaveAs $collectiondir\$collection\$collection-$malproc.csv
Wait-Process -name "Procmon"
Set-Location $collectiondir\$collection
Get-ChildItem
Write-host ""
Write-host "
** End of automation **" -Fore yellow