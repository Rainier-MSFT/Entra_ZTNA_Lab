<#  Common_Configs.ps1
    Rainier Amara 9/1/23
    This script applies a bunch of pre-configurations to each VM, post ARM deployment.
#>

# Relax PSH signing policy
#Set-ExecutionPolicy -ExecutionPolicy unrestricted -force

## Enable TLS1.2 (Connectivity - Critical)
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.2"
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -Name "Client"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 00000000 -PropertyType "DWord"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 00000001 -PropertyType "DWord"
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -Name "Server"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 00000000 -PropertyType "DWord"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 00000001 -PropertyType "DWord"
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 00000001 -PropertyType "Dword"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Disable IE Enhanced Security Config (Internet access - Optional)
Write-Host "Disabling IE Enhanced Security Configuration (ESC)..."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
#Stop-Process -Name Explorer

## Relax UAC (Optional)
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

## Install Microsoft Edge (If server 2016 - Optional)
$MSEdgeExe = (Get-ChildItem -Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue)
If ( -Not [System.IO.File]::Exists($MSEdgeExe.FullName)) {
    ## Download & install Edge Browser
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/68c5e2fb-3fa9-493b-a593-69ab63bd2651/MicrosoftEdgeEnterpriseX64.msi" -Destination "C:\Users\Public\Downloads\MicrosoftEdgeEnterpriseX64.msi"
    MsiExec.exe /i "C:\Users\Public\Downloads\MicrosoftEdgeEnterpriseX64.msi" /qn
    ## Disable Internet Explorer (Disable only to retain IE legacy mode in Edge)
    dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
    #stop-process -name explorer -force
}

## Download Azure AD Connect (If DC - Optional)
If ( Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'" ) {
Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi" -Destination "C:\Users\Public\Desktop\Install Azure AD Connect.msi"

## Drop Azure AD Connect portal link on desktop (Optional)
$ShortcutPath = "C:\Users\Public\Desktop\AAD Sync Portal.lnk"
$WScriptObj = New-Object -ComObject ("WScript.Shell")
$shortcut = $WscriptObj.CreateShortcut($ShortcutPath)
$shortcut.TargetPath = $MSEdgeExe
$ShortCut.Arguments = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/AzureADConnect"
$shortcut.WindowStyle = 1
$ShortCut.IconLocation = "%SystemRoot%\system32\SHELL32.dll, 238";
$ShortCut.Hotkey = 'CTRL+SHIFT+T';
$shortcut.Save()
}

## Install AD Certificate Services on DC
#if ($env:computername -like "*DC*") {
#Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
#Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force
#}

## Instanstiate test apps on App VM
if ($env:computername -like "*APP*") {
## Can be customized ensure the folder path has trailing "\" 
$destinationDirectory ="c:\AppDemov1\"
if ([int]$PSVersionTable.PSVersion.Major -lt 5)
{
    Write-Host "Minimum required version is PowerShell 5.0"
    Write-Host "Refer https://aka.ms/wmf5download"
    Write-Host "Program will terminate now .."
    exit
}
#[string] $AppProxyConnector =  Read-Host "AppProxy Connector Machine Netbios Name ( used for KCD Config )" 
[string] $AppProxyConnector = "Ignore"
##Donot Modify 
function Invoke-Script
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Script,

        [Parameter(Mandatory = $false)]
        [object[]]
        $ArgumentList
    )

    $ScriptBlock = [Scriptblock]::Create((Get-Content $Script -Raw))
    Invoke-Command -NoNewScope -ArgumentList $ArgumentList -ScriptBlock $ScriptBlock -Verbose
}
[string]$kickStartFolder = $destinationDirectory + "DemoSuite-master\Website\"
[string]$kickStartScript = $kickStartFolder + "install.ps1"
Import-Module BitsTransfer
Start-BitsTransfer -Source 'https://github.com/jeevanbisht/DemoSuite/archive/master.zip' -Destination "$env:TEMP\master.zip";
New-Item -Force -ItemType directory -Path $destinationDirectory
Expand-Archive  "$env:TEMP\master.zip" -DestinationPath $destinationDirectory -Force 
$args = @()
$args += ("$kickStartFolder", "$AppProxyConnector")
Invoke-Script $kickStartScript $args
}
