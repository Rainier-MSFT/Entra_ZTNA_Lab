<#  XConfigs.ps1
    Rainier Amara 9/1/23
    This script applies a bunch of additional configurations to a deployed VM
DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE. Copyright (c) Microsoft Corporation.
#>

#param
#(    
#    [Parameter(Mandatory=$true)][string] $domainUserName,
#    [Parameter(Mandatory=$true)][string] $adminPassword
#)

## Enable TLS1.2 (Connectivity - Critical)
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.2"
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -Name "Client"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -PropertyType "DWord"
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -Name "Server"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType "DWord"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType "DWord"
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -PropertyType "Dword"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Relax UAC (Optional)
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0

## Disable IE Enhanced Security Config (Relax Internet access)
Write-Host "Disabling IE Enhanced Security Configuration (ESC)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0

## Install Microsoft Edge (If server 2016)
$MSEdgeExe = (Get-ChildItem -Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue)
If ( -Not [System.IO.File]::Exists($MSEdgeExe.FullName)) {
    ## Download & install Edge Browser
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/68c5e2fb-3fa9-493b-a593-69ab63bd2651/MicrosoftEdgeEnterpriseX64.msi" -Destination "$TmpDirectory\MicrosoftEdgeEnterpriseX64.msi"
    MsiExec.exe /i "$TmpDirectory\MicrosoftEdgeEnterpriseX64.msi" /qn
}

# Disable IE & EDGE 1st time run
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Edge" -Force
New-Itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType "DWord" -Force

## Drop icons
$TmpDirectory = "C:\Users\Public\Downloads"
Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Base-config_3-vm/resources/Icons.zip?raw=true" -Destination "$TmpDirectory\Icons.zip"
Expand-Archive "$TmpDirectory\Icons.zip" -DestinationPath $TmpDirectory -Force
If ($env:computername -like "*DC*") {
Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\DC\*" -Include "*.ico","*.msc")) {move-Item $file "C:\Windows\System32\"}
Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\DC\*" -Include "*.lnk","Cert Management*")) {move-Item $file "C:\Users\Public\Desktop\"}
} else {
Copy-Item "$TmpDirectory\Icons\APP\*" "C:\Users\Public\Desktop\"
}

## Azure AD sync link on DC
If ($env:computername -like "*DC*") {
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Install AAD Cloud Sync.lnk")
$Shortcut.TargetPath = "https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/GetStarted"
$ShortCut.IconLocation = "%SystemRoot%\system32\SHELL32.dll, 238"
$Shortcut.Save()
}

## Azure AD App Proxy Connector link on DC
If ($env:computername -like "*DC*") {
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Install App Proxy.lnk")
$Shortcut.TargetPath = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AppProxyOverviewBlade"
$ShortCut.IconLocation = "$TmpDirectory\connectors.ico"
$Shortcut.Save()
}

## Install AD Certificate Services on DC
if ($env:computername -like "*DC*") {
Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 3 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "c:\windows\system32\CertLog" -Force
}

## Disable Internet Explorer (Disabled only to retain IE legacy mode in Edge)
dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64