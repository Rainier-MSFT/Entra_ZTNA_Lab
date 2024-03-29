# <img align="left" src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/assets/6311098/47a893d3-e254-4a65-be16-176ae90be6e0" width=8%> Rapid Labs - Identity & Network Access

This repository offers a variety of Azure Resource Manager (ARM) based resources for quickly deploying lab environments for testing & learning about Microsoft Identity & Network Access capabilities.

ARM templates are pre-configured deployment packages that enable provisioning complex test environments in minutes, without requiring extensive PowerShell scripting or many hours of manual configuration. With little or no Azure experience, you can provision a whole virtual environment or individual VMs.

They're great for situations where you need to evaluate a solution or scenario before deploying to production, and having that "_I built it myself and it works_" hands-on experience also helps validate the requirements, before running a pilot or rolling out at scale. 

These templates are exclusively available thru this repository, but older ones can still be obtained via our [TLGs](http://aka.ms/catlgs).

## Azure Templates

| Template                     | Name                                                    | Description
| :-------------------         | :-------------------                                    | :-------------------
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_4-vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_4-vm)        | 4 VM Base Configuration | Deploys a 4 VM environment for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to private resources including remote access thru Azure AD Application Proxy or other technologies
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Apps_vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Apps_vm)        | Test Apps VM | Deploys a Windows Server VM pre-configured with several test applications & services for testing a variety of authN, authZ and SSO scenarios. Useful for scenarios where you already have an AD enviroment and require a bunch of pre-configured services for testing remote & local access thru Azure AD application Proxy or other technologies
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Client_vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Test-Client_vm)        | Test Client VM | Deploys a Windows client VM for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources. The template provisions a single VM with your prefered version of Windows, to an existing Azure VNet


## Prerequisites
Before deploying an ARM template, you'll need the following:

+ An Azure subscription and sufficient rights to deploy the given resources and specs for each template
+ Access to the Azure and Entra management portals https://entra.microsoft.com and https://portal.azure.com

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
