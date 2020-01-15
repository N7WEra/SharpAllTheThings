# SharpAllTheThings
The idea is to collect all the C# projects that are Sharp{Word} that can be used in Cobalt Strike as execute assembly command.
Credit the name to the amazing PayloadAllTheThings github repo (https://github.com/swisskyrepo/PayloadsAllTheThings)

### Execution
1. SharpWMI - implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SharpWMI
2. SharpGPOAbuse - take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
   * Credit - https://twitter.com/pkb1s
   * Link - https://github.com/FSecureLABS/SharpGPOAbuse

### Persistence
1. SharpPersist - Windows persistence toolkit written in C#. 
   * Credit - https://twitter.com/h4wkst3r
   * Link - https://github.com/fireeye/SharPersist

### Privilege Escalation
1. SharpUp -  port of various PowerUp functionality
   * Credit -  https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SharpUp

### Defense Evasion
1. SharpCradle - download and execute .NET binaries into memory.
   * Credit - https://twitter.com/anthemtotheego
   * Link - https://github.com/anthemtotheego/SharpCradle

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

### Discovery
1. SharpHound -  Uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment, executes collection options necessary to populate the backend BloodHound database. 
   * Credit -  The amazing crew of Bloodhound (https://www.twitter.com/\_wald0, https://twitter.com/CptJesus, and https://twitter.com/CptJesus)
   * Link - https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors
2. SharpWitness - C# version of EyeWitness by Christopher Truncer. Take screenshots of websites, provide some server header info, and identify default credentials if possible.
   * Credit - https://twitter.com/_RastaMouse
   * Link - https://github.com/rasta-mouse/SharpWitness
3. SharpDomainSpray -  very simple password spraying tool written in .NET. It takes a password then finds users in the domain and attempts to authenticate to the domain with that given password.
   * Credit - https://twitter.com/hunniccyber
   * Link - https://github.com/HunnicCyber/SharpDomainSpray
4. SharpSniper -  Find specific users in active directory via their username and logon IP address
   * Credit - https://twitter.com/hunniccyber
   * Link - https://github.com/HunnicCyber/SharpDomainSpray
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

### Exfiltration
1. SharpBox - Tool for compressing, encrypting, and exfiltrating data to DropBox using the DropBox API.
   * Credit -  https://twitter.com/_P1CKLES_
   * Link - https://github.com/P1CKLES/SharpBox



## Other projects which doesn't start with Sharp something but absolutely worth knowing about:
1. Rubeus - toolset for raw Kerberos interaction and abuses.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/Rubeus
2. SafetyKatz - combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
   * Credit - https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/SafetyKatz
3. Seatbelt - project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
   * Credit  -https://twitter.com/harmj0y
   * Link - https://github.com/GhostPack/Seatbelt
4. Watson -  Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
   * Credit - https://twitter.com/\_RastaMouse
   * Link - https://github.com/rasta-mouse/Watson
5. ADFSDump -  dump all sorts of goodies from AD FS.
   * Credit - https://twitter.com/doughsec
   * Link - https://github.com/fireeye/ADFSDump
6. OffensiveCSharp - Collection of Offensive C# Tooling
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp
7. CredSniper - Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function. Supports an argument to provide the message text that will be shown to the user.
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
8. EncryptedZIP -Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory. Use the included Decrypter progam to decrypt the archive.
   * Credit - https://twitter.com/matterpreter
   * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
9. SessionSearcher - Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details. Based on SessionGopher by @arvanaghi.
   * Credit - https://twitter.com/matterpreter
   * Link -https://github.com/matterpreter/OffensiveCSharp/tree/master/SearchSessions
10. UnquotedPath - Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into. 
    * Credit -https://twitter.com/matterpreter
    * Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/UnqoutedPath
11. Internal Monologue - Retrieving NTLM Hashes without Touching LSASS
    * Credit - https://www.twitter.com/elad_shamir
    * Link - https://github.com/eladshamir/Internal-Monologue
12. InveighZero - Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool
    * Credit - https://twitter.com/kevin_robertson
    * Link - https://github.com/Kevin-Robertson/InveighZero
13. SCShell - fileless lateral movement tool that relies on ChangeServiceConfigA to run commands.
    * Credit - https://twitter.com/MrUn1k0d3r
    * Link - https://github.com/Mr-Un1k0d3r/SCShell
14. ATPMiniDump - Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
    * Credit - https://twitter.com/b4rtik
    * Link - https://github.com/b4rtik/ATPMiniDump
15. RdpTheif - Extracting Clear Text Passwords from mstsc.exe using API Hooking.
    * Credit - https://twitter.com/0x09AL
    * Link - https://github.com/0x09AL/RdpThief
16. Spray-AD -  audit Active Directory user accounts for weak, well known or easy guessable passwords.
    * Credit - https://twitter.com/Cneelis
    * Link - https://github.com/outflanknl/Spray-AD
17. Recon-AD - an AD recon tool based on ADSI and reflective DLL’s
    * Credit - https://twitter.com/Cneelis
    * Link - https://github.com/outflanknl/Recon-AD
