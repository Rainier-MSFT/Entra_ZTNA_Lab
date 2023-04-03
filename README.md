# Identity & Network Access Labs

![TL logo](https://raw.githubusercontent.com/Rainier-MSFT/Entra_ZTNA_Lab/main/Base-config_3-vm/images/tlg.png "Rainier-MSFT")

This repository contains ARM templates used to deploy test lab environments for testing & learning about Microsoft Identity & Network Access capabilities away from production services. They're great for situations where you need to evaluate a technology or configuration before deciding whether to roll out at scale. The "I built it out myself and it works" hands-on experience helps you understand the deployment requirements of a new product or solution so you can better plan for hosting it in production. Some templates have been developed for specific target use cases that aren't available elsewhere, whilst others leverage the work of more well know sources such as [TLGs](http://aka.ms/catlgs).

Azure Resource Manager (ARM) templates are pre-configured prescriptive deployment packages that enable you to provision complex test/pilot environments in minutes that would otherwise require extensive PowerShell scripting or many hours of manual configuration. With little or no Azure experience, you can provision a standardized base environment for hands-on learning or to pilot integrated solutions.

## Azure Templates

| Template                     | Name                                                    | Description
| :-------------------         | :-------------------                                    | :-------------------
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_3-vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/Base-config_3-vm)        | 3 VM Base Configuration | This template deploys a 3 VM server & client environment that can be used for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources
| [](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/App-vm) [<img src="https://aka.ms/deploytoazurebutton">](https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/tree/main/App-vm)        | Test Apps VM | This template deploys a Windows Server VM pre-configured with several test applications & services for testing a variety of authN, authZ and SSO scenarios

## Prerequisites

Before you deploy an ARM template in this repository, you need to have:

+ Access to an Azure subscription with sufficient resources to deploy the template. Most templates in this repository require the following available resources:

  + 12 cores (4 cores per VM)
  + 1 storage account

  **Note:** Trial subscriptions do not have sufficient available resources for deployment of these templates.
+ A supported browser for access to the Azure portal (https://portal.azure.com). For more information, see [Supported browsers and devices for the Azure portal](https://docs.microsoft.com/en-us/azure/azure-preview-portal-supported-browsers-devices).
+ A public domain name and administrative access to the domain's DNS records.

Some templates may have additional requirements specified in the template's README.

___

## Disclaimers

All code in this repo is public (read-only to non-contributors). All templates in the master branch of this repo have been tested and should deploy successfully, subject to limitations and known issues described in each template's README.

This project welcomes suggestions, but is currently closed to outside contributions. To report an issue, make a suggestion for additional templates, or to request updates to existing templates, please visit the [issues page](https://github.com/maxskunkworks/TLG/issues).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
___

Developed by the **ZTNA CxP team** and sourced from the **Office 365 Commercial Content Experience team**.

Last update: _11/12/2018_
