# SharpAllTheThings
The idea is to collect all the C# projects that are Sharp{Word} that can be used in Cobalt Strike as execute assembly command.

# Execution
- SharpWMI - implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods.
Credit - https://twitter.com/harmj0y
Link - https://github.com/GhostPack/SharpWMI
- SharpGPOAbuse - take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.
Credit - https://twitter.com/pkb1s
Link - https://github.com/FSecureLABS/SharpGPOAbuse

# Persistence
- SharpPersist - Windows persistence toolkit written in C#. 
Credit - https://twitter.com/h4wkst3r
Link - https://github.com/fireeye/SharPersist

# Privilege Escalation
- SharpUp -  port of various PowerUp functionality
Credit -  https://twitter.com/harmj0y
Link - https://github.com/GhostPack/SharpUp

# Defense Evasion
- SharpCradle - download and execute .NET binaries into memory.
Credit - https://twitter.com/anthemtotheego
Link - https://github.com/anthemtotheego/SharpCradle

# Credential Access
- SharpLocker - helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike.
Credit -  https://twitter.com/Mattspickford
Link - https://github.com/Pickfordmatt/SharpLocker
- SharpDPAPI - port of some DPAPI functionality from @gentilkiwi's Mimikatz project.
Credit - https://twitter.com/harhttps://twitter.com/CptJesusmj0y
Link - https://github.com/GhostPack/SharpDPAPI
- SharpDump -  port of PowerSploit's Out-Minidump.ps1 functionality.
Credit - https://twitter.com/harmj0y
Link - https://github.com/GhostPack/SharpDump
- SharpWeb - Retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge.
Credit - https://twitter.com/djhohnstein
Link - https://github.com/djhohnstein/SharpWeb

# Discovery
- SharpHound -  Uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment, executes collection options necessary to populate the backend BloodHound database. 
Credit -  The amazing crew of Bloodhound (https://www.twitter.com/_wald0, https://twitter.com/CptJesus, and https://twitter.com/CptJesus)
Link - https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors
- SharpWitness - C# version of EyeWitness by Christopher Truncer. Take screenshots of websites, provide some server header info, and identify default credentials if possible.
Credit - https://twitter.com/_RastaMouse
Link - https://github.com/rasta-mouse/SharpWitness
- SharpDomainSpray -  very simple password spraying tool written in .NET. It takes a password then finds users in the domain and attempts to authenticate to the domain with that given password.
Credit - https://twitter.com/hunniccyber
Link - https://github.com/HunnicCyber/SharpDomainSpray
- SharpSniper -  Find specific users in active directory via their username and logon IP address
Credit - https://twitter.com/hunniccyber
Link - https://github.com/HunnicCyber/SharpDomainSpray
- SharpFruit - Port of Find-Fruit.ps1, aid Penetration Testers in finding juicy targets on internal networks without nmap scanning.
Credit - https://twitter.com/424f424f
Link - https://github.com/rvrsh3ll/SharpFruit
- SharpPrinter- tool to enumerate all visible network printers in local network
Credit - https://twitter.com/424f424f
Link - https://github.com/rvrsh3ll/SharpPrinter
- SharpView - C# implementation of harmj0y's PowerView
Credit - https://twitter.com/tevora
Link - https://github.com/tevora-threat/SharpView
- SharpSearch - Search files for extensions as well as text within.
Credit - https://twitter.com/djhohnstein
Link - https://github.com/djhohnstein/SharpSearch
- SharpClipHistory - Read the contents of a user's clipboard history in Windows 10 starting from the 1809 Build.
Credit- https://twitter.com/pkb1s
Link - https://github.com/FSecureLABS/SharpClipHistory

# Lateral Movement
- SharpCom -  port of Invoke-DCOM, Execute's commands via various DCOM methods as demonstrated by (@enigma0x3)
Credit - https://twitter.com/424f424f
Link - https://github.com/rvrsh3ll/SharpCOM
- Sharpexcel4_dcom - Port of Invoke-Excel4DCOM, Lateral movement using Excel 4.0 / XLM macros via DCOM (direct shellcode injection in Excel.exe)
Credit - https://twitter.com/424f424f
Link - https://github.com/rvrsh3ll/SharpExcel4-DCOM
- SharpExec - C# tool designed to aid with lateral movement
Credit - https://twitter.com/anthemtotheego?lang=en
Link - https://github.com/anthemtotheego/SharpExec

# Exfiltration
- SharpBox - Tool for compressing, encrypting, and exfiltrating data to DropBox using the DropBox API.
Credit -  https://twitter.com/_P1CKLES_
Link - https://github.com/P1CKLES/SharpBox

# Other projects which doesn't start with Sharp something but absolutely worth knowing about:
Rubeus - toolset for raw Kerberos interaction and abuses.
Credit - https://twitter.com/harmj0y
Link - https://github.com/GhostPack/Rubeus
SafetyKatz - combination of slightly modified version of @gentilkiwi's Mimikatz project and @subtee's .NET PE Loader.
Credit - https://twitter.com/harmj0y
Link - https://github.com/GhostPack/SafetyKatz
Seatbelt - project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
Credit  -https://twitter.com/harmj0y
Link - https://github.com/GhostPack/Seatbelt
Watson -  Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
Credit - https://twitter.com/_RastaMouse
Link - https://github.com/rasta-mouse/Watson
ADFSDump -  dump all sorts of goodies from AD FS.
Credit - https://twitter.com/doughsec
Link - https://github.com/fireeye/ADFSDump
OffensiveCSharp - Collection of Offensive C# Tooling
Credit - https://twitter.com/matterpreter
Link - https://github.com/matterpreter/OffensiveCSharp
CredSniper - Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function. Supports an argument to provide the message text that will be shown to the user.
Credit - https://twitter.com/matterpreter
Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
EncryptedZIP -Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory. Use the included Decrypter progam to decrypt the archive.
Credit - https://twitter.com/matterpreter
Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
SessionSearcher - Searches all connected drives for PuTTY private keys and RDP connection files and parses them for relevant details. Based on SessionGopher by @arvanaghi.
Credit - https://twitter.com/matterpreter
Link -https://github.com/matterpreter/OffensiveCSharp/tree/master/SearchSessions
UnquotedPath - Outputs a list of unquoted service paths that aren't in System32/SysWow64 to plant a PE into. 
Credit -https://twitter.com/matterpreter
Link - https://github.com/matterpreter/OffensiveCSharp/tree/master/UnqoutedPath
Internal Monologue - Retrieving NTLM Hashes without Touching LSASS
Credit - https://www.twitter.com/elad_shamir
Link - https://github.com/eladshamir/Internal-Monologue
InveighZero - Windows C# LLMNR/mDNS/NBNS/DNS spoofer/man-in-the-middle tool
Credit - https://twitter.com/kevin_robertson
Link - https://github.com/Kevin-Robertson/InveighZero
SCShell - fileless lateral movement tool that relies on ChangeServiceConfigA to run commands.
Credit - https://twitter.com/MrUn1k0d3r
Link - https://github.com/Mr-Un1k0d3r/SCShell
ATPMiniDump - Dumping LSASS memory with MiniDumpWriteDump on PssCaptureSnapShot to evade WinDefender ATP credential-theft.
Credit - https://twitter.com/b4rtik
Link - https://github.com/b4rtik/ATPMiniDump
RdpTheif - Extracting Clear Text Passwords from mstsc.exe using API Hooking.
Credit - https://twitter.com/0x09AL
Link - https://github.com/0x09AL/RdpThief
Spray-AD -  audit Active Directory user accounts for weak, well known or easy guessable passwords.
Credit - https://twitter.com/Cneelis
Link - https://github.com/outflanknl/Spray-AD
Recon-AD - an AD recon tool based on ADSI and reflective DLL’s
Credit - https://twitter.com/Cneelis
Link - https://github.com/outflanknl/Recon-AD
