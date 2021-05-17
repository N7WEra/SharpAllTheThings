# SharpAllTheThings
# Author: ZephrFish
# Description: Clones down all the git repos from SharpAllTheThings
## Written for WSL as it will use VS2019 to compile in BuildAllTheThings.bat
## Setup
mkdir SharpBuilderAll
cp BuildAllTheThings.bat SharpBuilderAll/
cd SharpBuilderAll
mkdir Execution
mkdir Persistence
mkdir PrivEsc
mkdir DefenseEvasion
mkdir CredAccess
mkdir Discovery
mkdir LateralMovement
mkdir Exfil
#
## Execution
git clone https://github.com/GhostPack/SharpWMI Execution/SharpWMI
git clone https://github.com/FSecureLABS/SharpGPOAbuse Execution/SharpGPOAbuse
#
## Persistence 
git clone https://github.com/fireeye/SharPersist Persistence/SharPersist
git clone https://github.com/0xthirteen/SharpStay Persistence/SharpStay
#
## Privilege Escalation 
git clone https://github.com/GhostPack/SharpUp PrivEsc/SharpUp 
git clone https://github.com/GhostPack/Seatbelt PrivEsc/Seatbelt
git clone https://github.com/rasta-mouse/Watson PrivEsc/Watson
git clone https://github.com/matterpreter/OffensiveCSharp/ OffensiveCSharp
git clone https://github.com/CCob/SweetPotato PrivEsc/SweetPotato
#
## Defense Evasion 
git clone https://github.com/anthemtotheego/SharpCradle DefenseEvasion/SharpCradle
git clone https://github.com/eladshamir/Internal-Monologue DefenseEvasion/Internal-Monologue
git clone https://github.com/b4rtik/ATPMiniDump DefenseEvasion/ATPMiniDump
git clone https://github.com/cube0x0/SharpeningCobaltStrike DefenseEvasion/SharpeningCobaltStrike
git clone https://github.com/Soledge/BlockEtw DefenseEvasion/BlockEtw
git clone https://github.com/PwnDexter/SharpEDRChecker DefenseEvasion/SharpEDRChecker
git clone https://github.com/CCob/SharpBlock DefenseEvasion/SharpBlock
git clone https://github.com/matterpreter/DefenderCheck
#
## Credential Access 
git clone https://github.com/Pickfordmatt/SharpLocker CredAccess/SharpLocker
git clone https://github.com/GhostPack/SharpDPAPI CredAccess/SharpDPAPI
git clone https://github.com/GhostPack/SharpDump CredAccess/SharpDump
git clone https://github.com/djhohnstein/SharpWeb CredAccess/SharpWeb
git clone https://github.com/m0rv4i/SharpCookieMonster CredAccess/SharpCookieMonster
git clone https://github.com/GhostPack/SafetyKatz CredAccess/SafetyKatz
git clone https://github.com/GhostPack/Rubeus CredAccess/Rubeus
git clone https://github.com/0x09AL/RdpThief CredAccess/RdpThief
git clone https://github.com/G0ldenGunSec/SharpSecDump CredAccess/SharpSecDump
git clone https://github.com/r3nhat/SharpWifiGrabber CredAccess/SharpWifiGrabber
#
## Discovery 
git clone https://github.com/BloodHoundAD/SharpHound3 Discovery/SharpHound3
git clone https://github.com/rasta-mouse/SharpWitness Discovery/SharpWitness
git clone https://github.com/HunnicCyber/SharpDomainSpray Discovery/SharpDomainSpray
git clone https://github.com/HunnicCyber/SharpSniper Discovery/SharpSniper
git clone https://github.com/rvrsh3ll/SharpFruit Discovery/SharpFruit
git clone https://github.com/rvrsh3ll/SharpPrinter Discovery/SharpPrinter
git clone https://github.com/tevora-threat/SharpView Discovery/SharpView
git clone https://github.com/djhohnstein/SharpSearch Discovery/SharpSearch
git clone https://github.com/FSecureLABS/SharpClipHistory Discovery/SharpClipHistory
git clone https://github.com/slyd0g/SharpClipboard Discovery/SharpClipboard
git clone https://github.com/djhohnstein/SharpChromium Discovery/SharpChromium
git clone https://github.com/fireeye/ADFSDump Discovery/ADFSDump
git clone https://github.com/Kevin-Robertson/InveighZero Discovery/InveighZero
git clone https://github.com/outflanknl/Spray-AD Discovery/Spray-AD
git clone https://github.com/outflanknl/Recon-AD Discovery/Recon-AD
git clone https://github.com/l0ss/Grouper2 Discovery/Grouper2
git clone https://github.com/cube0x0/SharpMapExec Discovery/SharpMapExec
#
## Lateral Movement 
git clone https://github.com/rvrsh3ll/SharpCOM LateralMovement/SharpCOM
git clone https://github.com/rvrsh3ll/SharpExcel4-DCOM LateralMovement/SharpExcel4-DCOM
git clone https://github.com/anthemtotheego/SharpExec LateralMovement/SharpExec
git clone https://github.com/0xthirteen/SharpRDP LateralMovement/SharpRDP
git clone https://github.com/0xthirteen/SharpMove LateralMovement/SharpMove
git clone https://github.com/Mr-Un1k0d3r/SCShell LateralMovement/SCShell
#
## Exfiltration 
git clone https://github.com/P1CKLES/SharpBox Exfil/SharpBox
git clone https://github.com/outflanknl/Zipper Exfil/Zipper
# Finished
echo "Go Forth and Build!"
# This will drop into a cmd.exe process from WSL and proceed to build the SLN files, this is still WIP
cmd.exe /c 'BuildAllTheThings.bat'
