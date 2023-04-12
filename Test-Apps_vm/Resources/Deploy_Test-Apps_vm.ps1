<#  Deploy_Test-App_vm.ps1
    Rainier Amara 9/1/23
    This script deploys a single Test application VM to your Azure RM subscription.
    You must have the AzureRM PowerShell module installed on your computer to run this script.
    To install the AzureRM module, execute the following command from an elevated PowerShell prompt:
    Install-Module AzureRM
DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE. Copyright (c) Microsoft Corporation.
#>

# Provide parameter values
$subscription = "subscription name"
$resourceGroup = "resource group name"
$location = "location, i.e. UK South"

$configName = "" # The name of the deployment, i.e. BaseConfig-01. Do not use spaces or special characters other than _ or -. Used to concatenate resource names for the deployment
$domainName = "" # The FQDN of the new AD domain
$serverOS = "2016-Datacenter" # The OS of application servers in your deployment, i.e. 2016-Datacenter or 2012-R2-Datacenter
$adminUserName = "" # The name of the domain administrator account to create, i.e. globaladmin
$adminPassword = "" # The administrator account password
$vmSize = "Standard_B2s" # Select a VM size for all server VMs in your deployment
$dnsLabelPrefix = "" # DNS label prefix for public IPs. Must be lowercase and match the regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$
$_artifactsLocation = "https://raw.githubusercontent.com/Rainier-MSFT/Entra_ZTNA_Lab/main/Test-Apps_vm/" # Location of template artifacts
$_artifactsLocationSasToken = "" # Enter SAS token here if needed
$templateUri = "$_artifactsLocation/azuredeploy.json"
$privateIPAddress = "" # Static IP Address to allocate VM. Must fall within subnet range
$VnetName = "" # Name of Azure VNet the VM Subnet belongs to, within the same Resource Group
$subnetName = "" # Name of Subnet the VM will be connected to, within the same Resource Group
$DNSip = "" # IP of internal DNS server

# Add parameters to array
$parameters = @{}
$parameters.Add("configName",$configName)
$parameters.Add("domainName",$domainName)
$parameters.Add("serverOS",$serverOS)
$parameters.Add("adminUserName",$adminUserName)
$parameters.Add("adminPassword",$adminPassword)
$parameters.Add("deployClientVm",$deployClientVm)
$parameters.Add("clientVhdUri",$clientVhdUri)
$parameters.Add("vmSize",$vmSize)
$parameters.Add("dnsLabelPrefix",$dnsLabelPrefix)
$parameters.Add("_artifactsLocation",$_artifactsLocation)
$parameters.Add("_artifactsLocationSasToken",$_artifactsLocationSasToken)
$parameters.Add("privateIPAddress",$privateIPAddress)
$parameters.Add("VnetName",$VnetName)
$parameters.Add("subnetName",$subnetName)
$parameters.Add("DNSip",$DNSip)

# Log in to Azure subscription
Connect-AzureRmAccount
Select-AzureRmSubscription -SubscriptionName $subscription

# Deploy template
New-AzureRmResourceGroupDeployment -Name $configName -ResourceGroupName $resourceGroup `
  -TemplateUri $templateUri -TemplateParameterObject $parameters -DeploymentDebugLogLevel All