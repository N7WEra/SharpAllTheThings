# SharpAllTheThings
The idea is to collect all the C# projects that are Sharp{Word} that can be used in Cobalt Strike as execute assembly command.
Credit the name to the amazing PayloadAllTheThings github repo (https://github.com/swisskyrepo/PayloadsAllTheThings)

## Build locally (Credit to [ZephrFish](https://twitter.com/ZephrFish))
You can use [ZephrFish](https://twitter.com/ZephrFish) script to download the scripts and build locally, this can be done by following these instructions:
https://github.com/N7WEra/SharpAllTheThings/blob/master/BuildAllTheThings/README.md

## Precompiled binaries
You can find nightly builds of most of the tools in this awsome repo by [Flangvik](https://twitter.com/Flangvik)

https://github.com/Flangvik/SharpCollection

### Execution
1. SharpWMI - implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SharpWMI
2. SharpGPOAbuse - take advantage of a user's edit rights on a Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
   * Credit - https://twitter.com/pkb1s
   * Link - https://github.com/FSecureLABS/SharpGPOAbuse

### Persistence
1. SharpPersist - Windows persistence toolkit written in C#. 
   * Credit - https://twitter.com/h4wkst3r
   * Link - https://github.com/fireeye/SharPersist
2. SharpStay - .NET project for installing Persistence
   * Credit - https://twitter.com/0xthirteen
   * Link - https://github.com/0xthirteen/SharpStay
 
### Privilege Escalation
1. SharpUp -  port of various PowerUp functionality
   * Credit -  https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SharpUp
2. Seatbelt - project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
   * Credit  -https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/Seatbelt
3. Watson -  Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
   * Credit - https://twitter.com/\_RastaMouse
   * Link - https://github.com/rasta-mouse/Watson
4. UnquotedPath - Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into. 
    * Credit -https://twitter.com/matterpreter
    * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/UnqoutedPath
5. SweetPotato - Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
    * Credit - https://twitter.com/_EthicalChaos_
    * Link - https://github.com/CCob/SweetPotato
6. AtYourService - Queries all services on a host and filters out services running as LocalSystem, NT Authority\LocalService, and NT Authority\NetworkService
    * Credit - https://twitter.com/midi_v2
    * Link - https://github.com/mitchmoser/AtYourService

### Defense Evasion
1. SharpCradle - download and execute .NET binaries into memory.
   * Credit - https://twitter.com/anthemtotheego
   * Link - https://github.com/anthemtotheego/SharpCradle
2. Internal Monologue - Retrieving NTLM Hashes without Touching LSASS
    * Credit - https://www.twitter.com/elad_shamir
    * Link - https://github.com/eladshamir/Internal-Monologue
3. ATPMiniDump - Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
    * Credit - https://twitter.com/b4rtik
    * Link - https://github.com/b4rtik/ATPMiniDump
4. SharpeningCobaltStrike - in realtime v35/40 dotnet compiler for your linux Cobalt Strike C2. New fresh compiled and obfuscated binary for each use.
    * Credit - https://twitter.com/cube0x0
    * Link - https://github.com/cube0x0/SharpeningCobaltStrike
4. BlockEtw - .Net Assembly to block ETW telemetry in current process
    * Credit - https://twitter.com/Sol_Secure
    * Link - https://github.com/Soledge/BlockEtw
5. SharpEDRChecker - Checks running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services, the registry and running drivers for the presence of known defensive products such as AV's, EDR's and logging tools.
    * Credit - https://twitter.com/PwnDexter
    * Link - https://github.com/PwnDexter/SharpEDRChecker
5. SharpBlock - SharpBlock can be used to load a child process and prevent any DLL from hooking into the child process. 
    * Credit - https://twitter.com/_EthicalChaos_
    * Link - https://github.com/CCob/SharpBlock

### Credential Access
1. SharpLocker - helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike.
   * Credit -  https://twitter.com/Mattspickford
   * Link - https://github.com/Pickfordmatt/SharpLocker
2. SharpDPAPI - port of some DPAPI functionality from @gentilkiwi's Mimikatz project.
   * Credit - https://twitter.com/harhttps://twitter.com/CptJesusmj0y
   * Link - https://github.com/GhostPack/SharpDPAPI
3. SharpDump -  port of PowerSploit's Out-Minidump.ps1 functionality.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SharpDump
4. SharpWeb - Retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.
   * Credit - https://twitter.com/djhohnstein
   * Link - https://github.com/djhohnstein/SharpWeb
4. SharpCookieMonster - Extracts cookies from Chrome.
   * Credit - https://twitter.com/m0rv4i , original work by @defaultnamehere
   * Link - https://github.com/m0rv4i/SharpCookieMonster
5. SafetyKatz - combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SafetyKatz
6. CredSniper - Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function. Supports an argument to provide the message text that will be shown to the user.
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
7. Rubeus - toolset for raw Kerberos interaction and abuses.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/Rubeus
8. RdpTheif - Extracting Clear Text Passwords from mstsc.exe using API Hooking.
    * Credit - https://twitter.com/0x09AL
    * Link - https://github.com/0x09AL/RdpThief
9. SharpSecDump - port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py.
    * Credit - https://twitter.com/G0ldenGunSec
    * Link - https://github.com/G0ldenGunSec/SharpSecDump
10. SharpWifiGrabber - Sharp Wifi Password Grabber retrieves in clear-text the Wi-Fi Passwords from all WLAN Profiles saved on a workstation using native win32 API.
    * Credit - https://twitter.com/r3n_hat
    * Link - https://github.com/r3nhat/SharpWifiGrabber
11. SharpHandler - tool for stealing/duping handles to LSASS
    * Credit - https://twitter.com/Jean_Maes_1994
    * Link - https://github.com/jfmaes/SharpHandler
12. SharpLAPS - etrieve the LAPS password from the Active Directory for accounts with ExtendedRight or Generic All Rights
    * Credit - https://twitter.com/pentest_swissky
    * Link - https://github.com/swisskyrepo/SharpLAPS
13. BetterSafetyKatz - modified fork of SafetyKatz dynamically fetches the latest pre-compiled release of Mimikatz directly from the gentilkiwi GitHub repo, runtime patching on detected signatures and uses SharpSploit DInvoke to get it into memory.
    * Credit - https://twitter.com/Flangvik
    * Link - https://github.com/Flangvik/BetterSafetyKatz
14. SharpKatz - Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands
    * Credit - https://twitter.com/b4rtik
    * Link - https://github.com/b4rtik/SharpKatz
15. SharpMiniDump - Create a minidump of the LSASS process from memory (Windows 10 - Windows Server 2016). The entire process uses: dynamic API calls, direct syscall and Native API unhooking to evade the AV / EDR detection.
    * Credit - https://twitter.com/b4rtik
    * Link - https://github.com/b4rtik/SharpMiniDump

### Discovery
1. SharpHound -  Uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment, executes collection options necessary to populate the backend BloodHound database. 
   * Credit -  The amazing crew of Bloodhound (https://www.twitter.com/\_wald0, https://twitter.com/CptJesus, and https://twitter.com/CptJesus)
   * Link - https://github.com/BloodHoundAD/SharpHound3
2. SharpWitness - C# version of EyeWitness by Christopher Truncer. Take screenshots of websites, provide some server header info, and identify default credentials if possible.
   * Credit - https://twitter.com/_RastaMouse
   * Link - https://github.com/rasta-mouse/SharpWitness
3. SharpDomainSpray -  very simple password spraying tool written in .NET. It takes a password then finds users in the domain and attempts to authenticate to the domain with that given password.
   * Credit - https://twitter.com/hunniccyber
   * Link - https://github.com/HunnicCyber/SharpDomainSpray
4. SharpSniper -  Find specific users in active directory via their username and logon IP address
   * Credit - https://twitter.com/hunniccyber
   * Link - https://github.com/HunnicCyber/SharpSniper
5. SharpFruit - Port of Find-Fruit.ps1, aid Penetration Testers in finding juicy targets on internal networks without nmap scanning.
   * Credit - https://twitter.com/424f424f
   * Link - https://github.com/rvrsh3ll/SharpFruit
6. SharpPrinter- tool to enumerate all visible network printers in local network
   * Credit - https://twitter.com/424f424f
   * Link - https://github.com/rvrsh3ll/SharpPrinter
7. SharpView - C# implementation of harmj0y's PowerView
   * Credit - https://twitter.com/tevora
   * Link - https://github.com/tevora-threat/SharpView
8. SharpSearch - Search files for extensions as well as text within.
   * Credit - https://twitter.com/djhohnstein
   * Link - https://github.com/djhohnstein/SharpSearch
9. SharpClipHistory - Read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
   * Credit- https://twitter.com/pkb1s
   * Link - https://github.com/FSecureLABS/SharpClipHistory
10. SharpClipboard - Monitor of the clipboard for any passwords
    * Credit- https://twitter.com/slyd0g
    * Link - https://github.com/slyd0g/SharpClipboard
11. SharpChromium - .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins.
    * Credit - https://twitter.com/djhohnstein
    * Link - https://github.com/djhohnstein/SharpChromium
12. ADFSDump -  dump all sorts of goodies from AD FS.
    * Credit - https://twitter.com/doughsec
    * Link - https://github.com/fireeye/ADFSDump
13. SessionSearcher - Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details. Based on SessionGopher by @arvanaghi.
    * Credit - https://twitter.com/matterpreter
    * Link -https://github.com/matterpreter/OffensiveCSharp/tree/master/SearchSessions
14. InveighZero - Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool
    * Credit - https://twitter.com/kevin_robertson
    * Link - https://github.com/Kevin-Robertson/InveighZero
15. EyeWitness - take screenshots of websites, provide some server header info, and identify default credentials if possible
    * Credit - https://twitter.com/Matt_Grandy_ and https://twitter.com/christruncer
    * Link - https://github.com/FortyNorthSecurity/EyeWitness
16. Spray-AD -  audit Active Directory user accounts for weak, well known or easy guessable passwords.
    * Credit - https://twitter.com/Cneelis
    * Link - https://github.com/outflanknl/Spray-AD
17. Recon-AD - an AD recon tool based on ADSI and reflective DLL’s
    * Credit - https://twitter.com/Cneelis
    * Link - https://github.com/outflanknl/Recon-AD
18. Grouper2 - A tool for pentesters to help find security-related misconfigurations in Active Directory Group Policy.
    * Credit - l0ss (@mikeloss) https://twitter.com/mikeloss
    * Link - https://github.com/l0ss/Grouper2/blob/master/README.md
19. SharpMapExec - A sharpen version of CrackMapExec. 
    * Credit - Cube0x0 https://twitter.com/cube0x0
    * Link - https://github.com/cube0x0/SharpMapExec
20. SharpSMBSpray - Spray a hash via smb to check for local administrator access.
    * Credit - rvrsh3ll https://twitter.com/424f424f
    * Link - https://github.com/rvrsh3ll/SharpSMBSpray
21. SauronEye - Search tool find specific files containing specific keywords (.doc, .docx, .xls, .xlsx)
    * Credit - https://twitter.com/_vivami
    * Link - https://github.com/vivami/SauronEye
22. SharpShare - Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain (Updated version)
    * Credit - https://twitter.com/midi_v2
    * Link - https://github.com/mitchmoser/SharpShares
23. SharpLDAP - C# .NET Assembly to perform LDAP Queries
    * Credit - https://twitter.com/midi_v2
    * Link - https://github.com/mitchmoser/SharpLDAPSearch
24. ADCollector - a lightweight tool that enumerates the Active Directory environment to identify possible attack vectors.
   * Credit - https://twitter.com/dev2nulI
   * Link - https://github.com/dev-2null/ADCollector
25. StandIn -  small AD post-compromise toolkit
   * Credit - https://twitter.com/FuzzySec
   * Link - https://github.com/FuzzySecurity/StandIn
26. TruffleSnout - iterative AD discovery toolkit for offensive operators
   * Credit - https://twitter.com/dsnezhkov
   * Link - https://github.com/dsnezhkov/TruffleSnout
27. ThunderFox - Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox
   * Credit - https://twitter.com/_theVIVI
   * Link - https://github.com/V1V1/SharpScribbles
   
### Lateral Movement
1. SharpCom -  port of Invoke-DCOM, Execute's commands via various DCOM methods as demonstrated by (@enigma0x3)
   * Credit - https://twitter.com/424f424f
   * Link - https://github.com/rvrsh3ll/SharpCOM
2. Sharpexcel4_dcom - Port of Invoke-Excel4DCOM, Lateral movement using Excel 4.0 / XLM macros via DCOM (direct shellcode injection in Excel.exe)
   * Credit - https://twitter.com/424f424f
   * Link - https://github.com/rvrsh3ll/SharpExcel4-DCOM
3. SharpExec - C# tool designed to aid with lateral movement
   * Credit - https://twitter.com/anthemtotheego?lang=en
   * Link - https://github.com/anthemtotheego/SharpExec
4. SharpRDP - Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
   * Credit - https://twitter.com/0xthirteen
   * Link - https://github.com/0xthirteen/SharpRDP
5. SharpMove - .NET Project for performing Authenticated Remote Execution
   * Credit - https://twitter.com/0xthirteen
   * Link - https://github.com/0xthirteen/SharpMove
6. SCShell - fileless lateral movement tool that relies on ChangeServiceConfigA to run commands.
    * Credit - https://twitter.com/MrUn1k0d3r
    * Link - https://github.com/Mr-Un1k0d3r/SCShell
7. SharpSphere - gives red teamers the ability to easily interact with the guest operating systems of virtual machines managed by vCenter. 
    * Credit - https://twitter.com/jkcoote
    * Link - https://github.com/JamesCooteUK/SharpSphere
8. Sharp-SMBExec - A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script
    * Credit - https://twitter.com/checkymander
    * Link - https://github.com/checkymander/Sharp-SMBExec
9. SharpNoPSExec- File less command execution for lateral movement.
    * Credit - https://twitter.com/juliourena
    * Link - https://github.com/juliourena/SharpNoPSExec
    

### Exfiltration
1. SharpBox - Tool for compressing, encrypting, and exfiltrating data to DropBox using the DropBox API.
   * Credit -  https://twitter.com/_P1CKLES_
   * Link - https://github.com/P1CKLES/SharpBox
2. EncryptedZIP -Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory. Use the included Decrypter progam to decrypt the archive.
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
3. Zipper - a CobaltStrike file and folder compression utility.
    * Credit - Cornelis de Plaa (@Cneelis) / Outflank
    * Link - https://github.com/outflanknl/Zipper

## Other projects
1. OffensiveCSharp - Collection of Offensive C# Tooling
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp
2. SharpAllowedToAct - implementation of a computer object takeover through Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
   * Credit - https://twitter.com/pkb1s
   * Link - https://github.com/pkb1s/SharpAllowedToAct

   

