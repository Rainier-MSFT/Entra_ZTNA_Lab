<#  XConfigs.ps1
    Rainier Amara 6/7/23
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

$TmpDirectory = "C:\Users\Public\Downloads"
$AllDesktop = ([Environment]::GetEnvironmentVariable("Public"))+"\Desktop\"

# Global pre-reqs
Add-WindowsFeature net-framework-core
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

## Provision icons
Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Base-config_4-vm/resources/Icons.zip?raw=true" -Destination "$TmpDirectory\Icons.zip"
Expand-Archive "$TmpDirectory\Icons.zip" -DestinationPath $TmpDirectory -Force

If ($env:computername -like "DC*") {
    # Install AD Certificate Services
    Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 3 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "c:\windows\system32\CertLog" -Force
    Certutiul -vroot

    # Install Entra Cloud Sync
    Invoke-WebRequest -Uri "https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/previewProvisioningAgentInstaller" -OutFile "$TmpDirectory\CloudSync.exe"
    Start-Process "$TmpDirectory\CloudSync.exe" /q

    ## Provision shortcuts
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "certificate*","connector*","*.msc")) {move-Item $file "C:\Windows\System32\"}
    Sleep (2)
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "Cert Management.*","AD Users and Computers*","DNS*","Cert Management*")) {move-Item $file $AllDesktop}
}

If ($env:computername -like "Connector*") {
    ## Download Entra Private Accesss Connector
    Invoke-WebRequest -Uri "https://download.msappproxy.net/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector/DownloadConnectorInstaller" -OutFile "$TmpDirectory\Connector.exe"
    ## Provision shortcuts
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "Connector*")) {move-Item $file "C:\Windows\System32\"}
    Sleep (2)
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "Install Private Access*")) {move-Item $file $AllDesktop}
}

If ($env:computername -like "Client*") {
    ## Download Entra Private Accesss client
    Invoke-WebRequest -Uri "https://download.msappproxy.net/Subscription/b8795d5c-2a52-4259-9dc9-bff6eb3e15d7/Connector/GlobalSecureAccessClientInstaller" -OutFile "$TmpDirectory\GlobalSecureAccessClient.exe"
    ## Provision shortcuts
    Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "Install Global*")) {move-Item $file $AllDesktop}
}

## Execute on APP VM (If called from app template)
If ( -not [string]::IsNullOrEmpty($domainAdmin)){
    $SadminPassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $Creds = New-Object System.Management.Automation.PSCredential ($domainAdmin, $SadminPassword)

    # Pre-reqs
    Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
    Add-windowsfeature web-server -includeallsubfeature
    Sleep (4)
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
    Copy-Item "$TmpDirectory\Icons\*" $AllDesktop

    # Deploy IIS apps
    $WWWroot = (Get-WebFilePath "IIS:\Sites\Default Web Site").Parent.FullName + "\"
    Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/resources/WebSites.zip?raw=true" -Destination "$TmpDirectory\WebSites.zip"
    Expand-Archive "$TmpDirectory\WebSites.zip" -DestinationPath $WWWroot -Force

    $HostDomain = Get-ADDomain -Current LocalComputer | Select-Object -ExpandProperty NetBIOSName

    Function appPoolcredName {
        [string] $Randz = -join ((65..90) + (97..122) | Get-Random -Count 4 | % {[char]$_})
        $Randz=$Randz.ToLower()
        $AppPooluName = "TestAppPool-$Randz"
        return $AppPooluName
    }

    Function passGen {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $false)][int]$Length = 10,
            [Parameter(Mandatory = $false)][string]$SamAccountName = $null,
            [Parameter(Mandatory = $false)][string]$DisplayName = $null
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
                # check for presence of... 
                # - Uppercase: A through Z, with diacritic marks, Greek and Cyrillic characters
                if ($password -cnotmatch "[A-Z\p{Lu}\s]") {
                    continue  # bad password, skip & try another one
                }
                # - Lowercase: a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters
                if ($password -cnotmatch "[a-z\p{Ll}\s]") {
                    continue  # bad password, skip and try another one
                }
                # - Base 10 digits (0 through 9)
                if ($password -notmatch "[\d]") {
                    continue  # bad password, skip & try another one
                }
                # - Nonalphanum characters: ~!@#$%^&*_-+=`|\(){}[]:;”‘<>,.?/
                if ($password -notmatch "[^\w]") {
                    continue  # bad password, skip and try another one
                }
            }
            # All tests succeeded so break loop
            break
        }
        # return new password
        $Password
    }

    # Site 1 setup
    [string] $SiteName = "IWAApp"
    [string] $SitePort = "8080"
    # Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Creds -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
    Set-WebConfigurationProperty -filter /system.webServer/security/authentication/windowsAuthentication -name enabled -value 1 -PSPath IIS:\ -location $SiteName
    Set-WebConfigurationProperty -filter /system.webServer/security/authentication/anonymousAuthentication -name enabled -value 0  -PSPath IIS:\ -location $SiteName
    Set-WebConfigurationProperty -filter /system.webServer/security/authentication/windowsAuthentication -Name useAppPoolCredentials -value 1 -PSPath IIS:\ -location $SiteName

    # Site 2 setup
    [string] $SiteName = "HeaderApp"
    [string] $SitePort = "8081"
    # Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Creds -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}

    # Site 3 setup
    [string] $SiteName = "FormsApp"
    [string] $SitePort = "8082"
    ## Create App Pool domain cred
    $AppPooluName = appPoolcredName
    $appPoolPword = passGen
    New-ADUser -Credential $Creds -Name $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account" -AccountExpirationDate $null
    New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
    sleep(2)
    New-Item -Path IIS:\AppPools\$SiteName
    sleep(1)
    Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
}

## Disable Internet Explorer (Disabled only to retain IE legacy mode in Edge)
## dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64

#Clean-up
Set-PSDebug -Trace 0
Stop-Transcript
#Sleep (2)
#Remove-Item -Path "$TmpDirectory\*" -recurse
Restart-computer -Force