<#  Deploy_Base-config_4-vm.ps1
    Rainier Amara 9/1/23
    This script deploys the 4 VM Base configuration lab to your Azure RM subscription.
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
$serverOS = "2016-Datacenter" # The OS of application servers in your deployment, i.e. 2016, 2019, or 2022
$adminUserName = "" # The name of the domain administrator account to create, i.e. globaladmin
$adminPassword = "" # The administrator account password
$deployClientVm = "Yes" # Yes or No
$clientVhdUri = "" # The URI of the storage account containing the client VHD. Leave blank if you are not deploying a client VM
$vmSize = "Standard_B2s" # Select a VM size for all server VMs in your deployment
$dnsLabelPrefix = "" # DNS label prefix for public IPs. Must be lowercase and match the regular expression: ^[a-z][a-z0-9-]{1,61}[a-z0-9]$
$_artifactsLocation = "https://raw.githubusercontent.com/Rainier-MSFT/Entra_ZTNA_Lab/main/Base-config_4-vm/" # Location of template artifacts
$_artifactsLocationSasToken = "" # Enter SAS token here if needed
$templateUri = "$_artifactsLocation/azuredeploy.json"
$enableBastion = "Yes" # Deploy a Bastion for VM management via a browser based RDP connection instead of exposing RDP directly to the WWW

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

# Log in to Azure subscription
Connect-AzureRmAccount
Select-AzureRmSubscription -SubscriptionName $subscription

# Deploy resource group
New-AzureRmResourceGroup -Name $resourceGroup -Location $location

# Deploy template
New-AzureRmResourceGroupDeployment -Name $configName -ResourceGroupName $resourceGroup `
  -TemplateUri $templateUri -TemplateParameterObject $parameters -DeploymentDebugLogLevel All