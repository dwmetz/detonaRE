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
[console]::ForegroundColor="Cyan"
## variable configuration:
$malwspath = "E:" ## malware source path
$malwdpath = "C:\Users\REM\Desktop\Malware\" ## malware destination path
$malware = "redline-76ca4a.exe" ## malware executable
$pcaptime = 180 ## duration in seconds for pcap capture
$toolsdir = "E:\Tools"
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
Write-Host "@dwmetz | $([char]0x00A9)2023 bakerstreetforensics.com"
Write-Host ""
Write-Host ""
Set-Location $malwspath
Copy-Item .\$malware $malwdpath
Set-Location $malwdpath
If (Test-Path -Path $malwspath\Collections) {
    Write-Host "Collections directory $malwspath\Collections"
}
Else {
    $null = mkdir $malwspath\Collections
    If (Test-Path -Path $malwspath\Collections) {
        Write-Host "Collections directory $malwspath\Collections created."
    }
    Else {
        Write-Host -For Cyan "Error creating directory."
    }
}
$tstamp = (Get-Date -Format "-yyyyMMddHHmm")
$collection = $env:computername+$tstamp
Write-host "
Initiating PCAP collection"
#Get the local IPv4 address
$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress
# Start 'pcap' capture
netsh trace start capture=yes IPv4.Address=$env:HostIP tracefile=E:\Collections\$collection.etl
Sleep 5
# Malware detonation
Write-host "
Detonating malware sample"
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
Write-host "
Terminating packet capture"
# Terminate .etl capture
netsh trace stop
Set-Location $toolsdir
# Magnet RESPONSE evidence triage collection
Write-host "
Initiating Magnet RESPONSE evidence collection"
.\MagnetRESPONSE.exe /accepteula /unattended /output:$malwspath\Collections /caseref:$collection /captureram /capturepagefile /capturevolatile /capturesystemfiles /captureextendedprocessinfo /saveprocfiles
Write-host "
[Collecting Evidence]"
Wait-Process -Name "MagnetRESPONSE"
# Terminate malware process
Write-host "
Terminating malware process"
Get-Process| Where-Object {$_.Name -Like $malware} | Stop-Process
# Convert .etl to .pcap
Write-host "
Converting .etl file to .pcap"
./etl2pcapng.exe $malwspath\Collections\$collection.etl $malwspath\Collections\$collection.pcap
Set-Location $malwspath\Collections
Get-ChildItem
Write-host ""
Write-host "** End of automation **"