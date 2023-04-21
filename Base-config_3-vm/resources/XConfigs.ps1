<#  XConfigs.ps1
    Rainier Amara 8/1/23
    This script applies a bunch of additional configurations to a deployed VM
DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE. Copyright (c) Microsoft Corporation.
#>
Set-PSDebug -Trace 2
Start-Transcript -OutputDirectory "C:\Users\Public\Downloads\PSlog.txt" -IncludeInvocationHeader

$TmpDirectory = "C:\Users\Public\Downloads"

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
    Start-BitsTransfer -Source "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/68c5e2fb-3fa9-493b-a593-69ab63bd2651/MicrosoftEdgeEnterpriseX64.msi" -Destination "C:\Users\Public\Downloads\MicrosoftEdgeEnterpriseX64.msi"
    MsiExec.exe /i "C:\Users\Public\Downloads\MicrosoftEdgeEnterpriseX64.msi" /qn
}

# Disable EDGE (& IE) 1st time run
Write-Host "Disabling EDGE (& IE) 1st time run..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Edge" -Force
New-Itemproperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Value 1 -PropertyType "DWord" -Force

## Install AD Certificate Services on DC
if ($env:computername -like "*DC*") {
Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 3 -DatabaseDirectory "C:\windows\system32\certLog" -LogDirectory "c:\windows\system32\CertLog" -Force
}

## Provision icons
Start-BitsTransfer -Source "https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Base-config_3-vm/resources/Icons.zip?raw=true" -Destination "$TmpDirectory\Icons.zip"
Expand-Archive "$TmpDirectory\Icons.zip" -DestinationPath $TmpDirectory -Force
Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "*.ico","*.msc")) {move-Item $file "C:\Windows\System32\"}
Foreach($file in (Get-ChildItem "$TmpDirectory\Icons\*" -Include "*.lnk","Cert Management*")) {move-Item $file "C:\Users\Public\Desktop\"}

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

## Disable Internet Explorer (Disabled only to retain IE legacy mode in Edge)
dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64

#Clean-up
Remove-Item -Path "$TmpDirectory\*" -recurse
Restart-computer -Force