
<# 
.DESCRIPTION
	Version: 1.0
	This PowerShell script installs IIS & a bunch of sample Websites 
    configured for various authentication schemes such as Integrated Windows
    Authentication (IWA), Headers, and Forms. iPerf is also installed for 
    testing network performance, along with an SMB network file share.  
.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE. Copyright (c) Microsoft Corporation.
#>

# Install iPerf
Import-Module BitsTransfer
Start-BitsTransfer -Source "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip" -Destination "C:\Users\Public\Downloads\iperf-3.1.3-win64.zip"
Expand-Archive "C:\Users\Public\Downloads\iperf-3.1.3-win64.zip" -DestinationPath "C:\iPerf" -Force
New-NetFirewallRule -DisplayName 'iPerf-Server-Inbound-TCP' -Direction Inbound -Protocol TCP -LocalPort 5201 -Action Allow | Enable-NetFirewallRule
New-NetFirewallRule -DisplayName 'iPerf-Server-Inbound-UDP' -Direction Inbound -Protocol UDP -LocalPort 5201 -Action Allow | Enable-NetFirewallRule
## Create iPerf starter on desktop
Set-Content "C:\Users\Public\Desktop\RuniPerf.bat" 'C:\iPerf\iperf-3.1.3-win64\iperf3.exe -s' -Encoding Ascii

# Deploy IIS apps
if ([int]$PSVersionTable.PSVersion.Major -lt 5)
{
    Write-Host "Minimum required version is PowerShell 5.0"
    Write-Host "Refer https://aka.ms/wmf5download"
    Write-Host "Program will terminate now .."
    exit
}
$WWWroot = (Get-WebFilePath "IIS:\Sites\Default Web Site").Parent.FullName + "\"
$TmpDirectory = 'C:\Users\Public\Downloads\TestApps'
Start-BitsTransfer -Source 'https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/Resources/TestApps.zip?raw=true' -Destination 'C:\Users\Public\Downloads\TestApps.zip'
Expand-Archive 'C:\Users\Public\Downloads\TestApps.zip' -DestinationPath $TmpDirectory -Force
Copy-Item -Path "$TmpDirectory\IISSites\*" -Destination $WWWroot -Recurse

$HostDomain = (Get-ADDomain -Identity (Get-WmiObject Win32_ComputerSystem).Domain).NetBIOSName

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
    #Set-ADComputer -Identity jbadp1  -PrincipalsAllowedToDelegateToAccount  $AppPoolUserNameObj
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

#Install Pre-reqs
Write-Progress -PercentComplete 5 -id 1 -Activity "Test Apps Installer " -Status "Installing Pre-reqs" 
Write-Progress -PercentComplete 1 -id 2 -Activity "Installing Prerequisites" -Status "Remote Admin Tools" 
Add-WindowsFeature RSAT-AD-Tools
Write-Progress -PercentComplete 50 -id 2 -Activity "Installing Completed" -Status "Remote Admin Tools" 
Write-Progress -PercentComplete 20 -id 1 -Activity "Test Apps Installer " -Status "Installing Pre-reqs" 
Write-Progress -PercentComplete 55 -id 2 -Activity "Installing Prerequisites" -Status "IIS" 
import-module servermanager
add-windowsfeature web-server -includeallsubfeature
Write-Progress -PercentComplete 99 -id 2 -Activity "Installing Completed" -Status "IIS" 
Write-Progress -PercentComplete 100 -id 2 -Activity "Module Loaded" -Status "IIS" 
Write-Progress -PercentComplete 50 -id 1 -Activity "Test Apps Installer " -Status "Start Config" 
Import-Module WebAdministration
Write-Progress -PercentComplete 5 -id 2 -Activity "Initialize Install" -Status "Read Config"
Write-Progress -PercentComplete 25 -id 2 -Activity "Initialize Install" -Status "Install IWA Website" 

# Site 1 Vars
[string] $SiteName = "IWAApp"
[string] $SitePort = "8080"
# Create App Pool domain cred
$AppPooluName = appPoolcredName
$appPoolPword = passGen
New-ADUser appPoolcredName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account " -AccountExpirationDate $null
# Gen site
New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
sleep(2)
New-Item -Path IIS:\AppPools\$SiteName
sleep(1)
Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
sleep(1)
Set-KerberosAuthForAppPool -WebSiteName $WebSiteName1
sleep(1)
Add-SPN -UserName $AppPooluName 

Write-Progress -PercentComplete 50 -id 2 -Activity "Initialize Install" -Status "Install HeaderApp Website"
# Site 2 vars
[string] $SiteName = "HeaderApp"
[string] $SitePort = "8081"
# Create App Pool domain cred
$AppPooluName = appPoolcredName
$appPoolPword = passGen
New-ADUser $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account " -AccountExpirationDate $null
# Gen site
New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
sleep(2)
New-Item -Path IIS:\AppPools\$SiteName
sleep(1)
Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
sleep(1)

Write-Progress -PercentComplete 75 -id 2 -Activity "Initialize Install" -Status "Deploy Forms App Website" 
# Site 3 vars
[string] $SiteName = "FormsApp"
[string] $SitePort = "8082"
## Create App Pool domain cred
$AppPooluName = appPoolcredName
$appPoolPword = passGen
New-ADUser $AppPooluName -enable 1 -ChangePasswordAtLogon 0 -PasswordNeverExpires 1 -AccountPassword (ConvertTo-SecureString -AsPlainText $appPoolPword -Force) -PassThru -Surname $AppPooluName -GivenName $AppPooluName  -Description "Test AppPool Account " -AccountExpirationDate $null
# Gen site
New-Item iis:\Sites\$SiteName -bindings @{protocol="http";bindingInformation=":"+$SitePort+":"} -PhysicalPath ("$WWWroot" + "$SiteName")
sleep(2)
New-Item -Path IIS:\AppPools\$SiteName
sleep(1)
Set-ItemProperty IIS:\AppPools\$SiteName -name processModel -value @{userName="$HostDomain\$AppPooluName";password=$AppPoolPword;identitytype=3}
sleep(1)

Write-Progress -PercentComplete 75 -id 2 -Activity "Initialize Install" -Status "Install ASP.net Core hosting Package" 
& "$TmpDirectory\dotnet-hosting-3.1.3-win.exe" /quiet
    
Write-Progress -PercentComplete 100 -id 1 -Activity "Test Apps Installer " -Status "Completing Config"
Write-Progress -PercentComplete 100 -id 2 -Activity "Config Started" -Status "Config complete!"