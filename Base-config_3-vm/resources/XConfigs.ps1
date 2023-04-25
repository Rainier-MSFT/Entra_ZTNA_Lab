<#  XConfigs.ps1
    Rainier Amara 8/1/23
    This script applies a bunch of additional configurations to a deployed VM
DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE. Copyright (c) Microsoft Corporation.
#>
Param
(    
    [Parameter(Mandatory=$false)][string] $domainAdmin,
    [Parameter(Mandatory=$false)][string] $adminPassword
)
Set-PSDebug -Trace 2
Start-Transcript -OutputDirectory "C:\Users\Public\Downloads\PSlog.txt" -IncludeInvocationHeader

$SadminPassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($domainAdmin, $SadminPassword)

$TmpDirectory = "C:\Users\Public\Downloads"

# Global pre-reqs
Add-WindowsFeature net-framework-core
#New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "Dword"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Relax UAC (Optional)
Write-Host "Disable UAC to avoid interupts..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0

## Disable IE Enhanced Security Config (Relax Internet access)
Write-Host "Disabling IE Enhanced Security Configuration (ESC)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0

## Install Microsoft Edge if missing
Write-Host "Download & Install Microsoft EDGE browser..."
$MSEdgeExe = (Get-ChildItem -Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue)
If ( -Not [System.IO.File]::Exists($MSEdgeExe.FullName)) {
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/68c5e2fb-3fa9-493b-a593-69ab63bd2651/MicrosoftEdgeEnterpriseX64.msi" -Destination "$TmpDirectory\MicrosoftEdgeEnterpriseX64.msi"
    MsiExec.exe /i "$TmpDirectory\MicrosoftEdgeEnterpriseX64.msi" /qn
}

# Disable EDGE (& IE) 1st time run
Write-Host "Disabling EDGE (& IE) 1st time run..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Edge" -Force
New-Itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType "DWord" -Force

#Set EDGE as default browser - Needs restart
Set-Content "C:\Windows\System32\defaultapplication.xml" '<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association ApplicationName="Microsoft Edge" ProgId="MSEdgeHTM" Identifier=".html"/>
  <Association ApplicationName="Microsoft Edge" ProgId="MSEdgeHTM" Identifier=".htm"/>
  <Association ApplicationName="Microsoft Edge" ProgId="MSEdgeHTM" Identifier="http"/>
  <Association ApplicationName="Microsoft Edge" ProgId="MSEdgeHTM" Identifier="https"/>
</DefaultAssociations>' -Encoding Ascii
<# ID value for different browsers
IE.HTTP
ChromeHTML
MSEdgeHTM
FirefoxHTML-308046B0AF4A39CB
#>
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$Name = "DefaultAssociationsConfiguration"
$value = 'C:\Windows\System32\defaultapplication.xml'
New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force | Out-Null

If ($env:computername -like "DC*") {
    # Install AD Certificate Services
    Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 3 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "c:\windows\system32\CertLog" -Force

    ## Provision icons
    Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Base-config_3-vm/resources/Icons.zip?raw=true" -Destination "$TmpDirectory\Icons.zip"
    Expand-Archive "$TmpDirectory\Icons.zip" -DestinationPath $TmpDirectory -Force
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "*.ico","*.msc")) {move-Item $file "C:\Windows\System32\"}
    Sleep (2)
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "*.lnk","Cert Management*")) {move-Item $file "C:\Users\Public\Desktop\"}
}

if ($env:computername -like "*APP*") {
    # Pre-reqs
    Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
    Add-windowsfeature web-server -includeallsubfeature
    Sleep (6)
    Import-module servermanager
    Import-Module -Name ActiveDirectory
    import-module servermanager
    Import-Module WebAdministration
    Start-BitsTransfer -Source https://download.visualstudio.microsoft.com/download/pr/ff658e5a-c017-4a63-9ffe-e53865963848/15875eef1f0b8e25974846e4a4518135/dotnet-hosting-3.1.3-win.exe -Destination "$TmpDirectory\dotnet-hosting-3.1.3-win.exe"
    & "$TmpDirectory\dotnet-hosting-3.1.3-win.exe" /quiet

    # Install iPerf
    Write-Host "Installing iPerf..."
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip" -Destination "C:\Users\Public\Downloads\iperf-3.1.3-win64.zip"
    Expand-Archive "C:\Users\Public\Downloads\iperf-3.1.3-win64.zip" -DestinationPath "C:\iPerf" -Force
    New-NetFirewallRule -DisplayName 'iPerf-Server-Inbound-TCP' -Direction Inbound -Protocol TCP -LocalPort 5201 -Action Allow | Enable-NetFirewallRule
    New-NetFirewallRule -DisplayName 'iPerf-Server-Inbound-UDP' -Direction Inbound -Protocol UDP -LocalPort 5201 -Action Allow | Enable-NetFirewallRule

    ## Provision icons
    Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/resources/Icons.zip?raw=true" -Destination "$TmpDirectory\Icons.zip"
    Expand-Archive "$TmpDirectory\Icons.zip" -DestinationPath $TmpDirectory -Force
    Copy-Item "$TmpDirectory\Icons\*" "C:\Users\Public\Desktop\"

    # Deploy IIS apps
    $WWWroot = (Get-WebFilePath "IIS:\Sites\Default Web Site").Parent.FullName + "\"
    Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/resources/WebSites.zip?raw=true" -Destination "$TmpDirectory\WebSites.zip"
    Expand-Archive "$TmpDirectory\WebSites.zip" -DestinationPath $WWWroot -Force

    $HostDomain = Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty NetBIOSName

    Function Set-KerberosAuthForAppPool{
        param(
            [Parameter(Mandatory=$true)][string]$WebSiteName 
            )

        [string]$IISAppConfigPath = "IIS:\Sites\$WebSiteName"
        
        #IWA authN config
        Set-WebConfigurationProperty -filter /system.webServer/security/authentication/windowsAuthentication -name enabled -value true -PSPath IIS:\ -location $WebSiteName
        Set-WebConfigurationProperty -filter /system.webServer/security/authentication/anonymousAuthentication -name enabled -value False  -PSPath IIS:\ -location $WebSiteName
        
        cd $env:windir\system32\inetsrv
        #.\appcmd.exe set config $SiteName -section:system.webServer/security/authentication/windowsAuthentication /useKernelMode:"False"  /commit:apphost 
        .\appcmd.exe set config $SiteName -section:system.webServer/security/authentication/windowsAuthentication /useAppPoolCredentials:"True"  /commit:apphost
    }

    Function Add-SPN { 
        param(
        [Parameter(Mandatory=$true)][string]$UserName
        )

        [string]$ShortSPN="http/"+ $env:COMPUTERNAME
        [string]$LongSPN="http/" + $env:COMPUTERNAME+"."+$env:USERDNSDOMAIN
        $Result = Get-ADObject -LDAPFilter "(SamAccountname=$UserName)" 
        Set-ADObject -Identity $Result.DistinguishedName -add @{serviceprincipalname=$ShortSPN} 
        Set-ADObject -Identity $Result.DistinguishedName -add @{serviceprincipalname=$LongSPN}
    }

    Function Add-KCD { 
        param(
        [Parameter(Mandatory=$true)][string]$AppPooluName,
        [Parameter(Mandatory=$true)][string]$AppProxyConnetor
        )
        $dc=Get-ADDomainController -Discover -DomainName $env:USERDNSDOMAIN
        $AppProxyConnetorObj= Get-ADComputer -Identity $AppProxyConnetor -Server $dc.HostName[0]
        $AppPoolUserNameObj = Get-ADObject -LDAPFilter "(SamAccountname=$AppPooluName)" 
        
        Set-ADUser -Identity $AppPoolUserNameObj -PrincipalsAllowedToDelegateToAccount $AppProxyConnetorObj
        #Set-ADComputer -Identity jbadp1 -PrincipalsAllowedToDelegateToAccount $AppPoolUserNameObj
        Get-ADUser -identity $AppPoolUserNameObj -Properties PrincipalsAllowedToDelegateToAccount
    }

    Function appPoolcredName {
        [string] $Randz = -join ((65..90) + (97..122) | Get-Random -Count 4 | % {[char]$_})
        $Randz=$Randz.ToLower()
        $AppPooluName = "TestAppPool-$Randz"
        return $AppPooluName
    }

    Function passGen {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $false)]
            [int]$Length = 10,

            [Parameter(Mandatory = $false)]
            [string]$SamAccountName = $null,

            [Parameter(Mandatory = $false)]
            [string]$DisplayName = $null
        )
        # [Microsoft.ActiveDirectory.Management.ADEntity]
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        $passwordLength = [math]::Max($Length, $passwordPolicy.MinPasswordLength)

        $count = 1
        while ($true) {
            Write-Verbose ("Generating valid password attempt: {0}" -f $count++)
            $password = -join ([char[]]"!@#$%^&*0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz" | Get-Random -Count $passwordLength)
            if (![string]::IsNullOrWhiteSpace($SamAccountName) -and $password -match $SamAccountName) {
                continue  # bad password, skip and try another one
            }
            if (![string]::IsNullOrWhiteSpace($DisplayName)) {
                # if ANY PART of the display name that is split by the characters below, the password should fail the complexity rules.
                $tokens = $DisplayName.Split(",.-,_ #`t")
                $bad = foreach ($token in $tokens) {
                    if (($token) -and ($password -match $token)) { $true; break }
                }
                if ($bad) { continue }  # bad password, skip and try another one
            }
            if ($passwordPolicy.ComplexityEnabled) {
                # check for presence of 
                # - Uppercase: A through Z, with diacritic marks, Greek and Cyrillic characters
                if ($password -cnotmatch "[A-Z\p{Lu}\s]") {
                    continue  # bad password, skip and try another one
                }
                # - Lowercase: a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters
                if ($password -cnotmatch "[a-z\p{Ll}\s]") {
                    continue  # bad password, skip and try another one
                }
                # - Base 10 digits (0 through 9)
                if ($password -notmatch "[\d]") {
                    continue  # bad password, skip and try another one
                }
                # - Nonalphanumeric characters: ~!@#$%^&*_-+=`|\(){}[]:;”‘<>,.?/
                if ($password -notmatch "[^\w]") {
                    continue  # bad password, skip and try another one
                }
            }
            # apparently all tests succeeded, so break out of the while loop
            break
        }
        # return the new password
        $Password
    }

    # Site 1 Vars
    [string] $SiteName = "IWAApp"
    [string] $SitePort = "8080"
    # Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Cred -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    # Gen site
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
    sleep(1)
    #Set-KerberosAuthForAppPool -WebSiteName $WebSiteName1
    #sleep(1)
    #Add-SPN -UserName $AppPooluName 

    # Site 2 vars
    [string] $SiteName = "HeaderApp"
    [string] $SitePort = "8081"
    # Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Cred -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    # Gen site
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
    sleep(1)

    # Site 3 vars
    [string] $SiteName = "FormsApp"
    [string] $SitePort = "8082"
    ## Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Cred -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    # Gen site
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
}

## Disable Internet Explorer (Disabled only to retain IE legacy mode in Edge)
dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64

#Clean-up
Stop-Transcript
#Sleep (2)
#Remove-Item -Path "$TmpDirectory\*" -recurse
Restart-computer -Force