# <img align="left" src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/assets/6311098/47a893d3-e254-4a65-be16-176ae90be6e0" width=6%> Rapid Labs - Identity & Network Access

This repository offers a variety of Azure Resource Manager (ARM) based resources for quickly deploying test lab environments for testing & learning about Microsoft Identity & Network Access capabilities.

ARM templates are pre-configured deployment packages that enable provisioning complex test environments in minutes, without requiring extensive PowerShell scripting or many hours of manual configuration. With little or no Azure experience, you can provision a whole VM environment or individual components.

They're great for situations where you need to evaluate a solution or config before deploying to production, and having that "_I built it myself and it works_" hands-on experience helps validate the requirements, before running a pilot or rolling out at scale. 

Some newer templates are exclusively available thru this repository, whilst others leverage older sources such as our [TLGs](http://aka.ms/catlgs).

## Azure Templates

| Template                     | Name                                                    | Description
| :-------------------         | :-------------------                                    | :-------------------
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_3-vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_3-vm)        | 3 VM Base Configuration | Deploys a 3 VM server & client environment that can be used for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources including remote access thru Azure AD Application Proxy or other technologies
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Apps_vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Apps_vm)        | Test Apps VM | Deploys a Windows Server VM pre-configured with several test applications & services for testing a variety of authN, authZ and SSO scenarios. Useful for scenarios where you already have an AD enviroment and require a bunch of pre-configured services for testing remote & local access thru Azure AD application Proxy or other technologies
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Client_vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Client_vm)        | Test Client VM | Deploys a Windows client VM for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources. The template provisions a single VM with your prefered version of Windows, to an existing Azure VNet


## Prerequisites
Before you deploy an ARM template in this repository, you need to have:

+ Access to an Azure subscription with sufficient resources to deploy the template. Most templates in this repository require the following available resources:

  + 4 cores per VM
  + 1 storage account

+ A supported browser for access to the Entra or Azure portals (https://entra.microsoft.com  /  https://portal.azure.com). See [Supported browsers and devices](https://docs.microsoft.com/en-us/azure/azure-preview-portal-supported-browsers-devices)
+ A public domain name and administrative access to the domain's DNS records

Some templates may have additional requirements specified in the template's README.

___

## Disclaimers

All code in this repo is public (read-only to non-contributors). All templates in the master branch of this repo have been tested and should deploy successfully, subject to limitations and known issues described in each template's README.

This project welcomes suggestions, but is currently closed to outside contributions. To report an issue, make a suggestion for additional templates, or to request updates to existing templates, please visit the [issues page](https://github.com/maxskunkworks/TLG/issues).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
___

Developed by the **Microsoft ZTNA CxP team**

Last update: _11/02/2023_
