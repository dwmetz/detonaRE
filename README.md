<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="158" width="311" src="BSF.png"/>
 <p>
  <h2>
   detonaRE
  </h2>
  <h5>
      Capture. Detonate. Collect.
   </h5>
<p>
<p>
 </div>
<div align="center">
  <img style="padding:0;vertical-align:bottom;" height="340" width="526" src="screenshot.png"/>
  <div align="left">
  <h5>

  From Latin - "to detonate"

   Functions:
  </h5>

- initiates .etl packet capture
- initiates Process Monitor with a filter applied for the malware to be detonated
- launches malware sample
- terminates packet capture after specified interval
- initiates evidence collection with Magnet RESPONSE (memory, process, and triage capture)
- terminates the malware process
- converts collected .etl file to .pcap with etl2pcapng.
- converts collected .pml to .csv

<h5>
   Prerequisites:
</h5>

>- [Magnet RESPONSE](https://support.magnetforensics.com/s/article/Collect-evidence-for-incident-response-investigations-with-Magnet-RESPONSE)
>- [etl2pcapng.exe](https://github.com/microsoft/etl2pcapng)
>- [procmon.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
>
```
## variable configuration:
$malwspath = "E:" ## malware source path
$malwdpath = "C:\Users\REM\Desktop\Malware\" ## malware destination path on target host
$malware = "malware.exe" ## malware executable
$pcaptime = 180 ## duration in seconds for pcap capture
$toolsdir = "E:\Tools" # tools directory
$collectiondir = "E:\Collections" ## output directory for collections
$procmonconfig = "$toolsdir\malw.pmc" ## Process Monitor configuration file
##
```


