
# RansomeBlaster

RansomeBlaster is a Zero Trust based Security tool developed for protecting Computers and Airgaped Sytems which are being used at Facilities Such as Hospitals , Nuclear Power Plant , Thermal Power Plant , Power Grid etc

RansomeBlaster assumes there is no purpose for downloading executables , programing languages file , shortcuts etc on Computers Sytems which are used in Hospital etc 
Ransome
RansomeBlaster scan for files which are recently downloaded and delete and User can also whitelist files which should not be deleted

RansomeBlaster actively Blocks all malicious IPs(Ips which are being used by ransomeware gangs etc)

RansomeBlaster actively deletes all scheduled processes

RansomeBlaster actively Scans for logs in Windows Eventmanager and send it User #RansomeBlaster-Alert Slack Channel 

RansomeBlaster actively blocks LOLBins executables which are being abused by hackers for various purposes such as privilege escalations etc

Ransome Blaster also blocks cmd.exe , wsl.exe and powershell.exe by assuming there is no purpose for using them in Computers used in Hospitals etc

## Installation
Backup ALL Files which you downloaded before using RansomeBlaster

Download from Github Release and run executable with Admin Privileges 

In this version RansomeBlaster requires either Slack or MS Teams (APIs) to report and send alerts

```bash

 if your organisation using MSTeams
 Create a Environment Variable 
 MSTeams_enabled add its value to True 
 Create another Environment Variable such as team_api_key , team_channel
 and team_channel_id and add their value respectively 


 if your organisation using Slack
 Create an environment variable slack_enabled and add it values as True and Create a another Environment variable slack_api_key and add its value


```
    
