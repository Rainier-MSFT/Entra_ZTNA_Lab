# <img align="left" src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/assets/6311098/47a893d3-e254-4a65-be16-176ae90be6e0" width=8%> Entra ZTNA Lab - Test Client VM

**Time to deploy**: Approx. 4 minutes <p dir='rtl' align='right'>21/03/2023</p>

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Client_vm%2Fazuredeploy.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton"/>
</a>
<a href="https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Client_vm%2Fazuredeploy.json" target="_blank">
<img src="images/deploytoazuregov.svg"/>
<a/>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Client_vm%2Fazuredeploy.json" target="_blank">
<img src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Client_vm/images/visualizebutton.svg"/>
</a><p>

This Azure automation deploys a **Test Client VM** for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources. The template provisions a single VM with your prefered version of Windows, to an existing Azure VNet.

The following ARM resources are deployed as part of the solution:

### VM
+ **Client**: Windows 10 or 11 joined to any Windows Active Diretory (AD) domain, or leave blank to remain in workgroup mode

### Networking
+ **Network interfaces**: 1 NIC and a prefered private IP address can be specified during deployment 
+ **Public IP addresses**: 1 static public IP if enabled during deployment

### Extensions
+ **JoinDomain** is used to join a specified domain
+ **BGInfo** displays session info on desktop wallpaper on all VMs, but only displays over direct RDP sessions and not over Azure Bastion
+ **iaaSAntimalware** is applied with basic scheduled scan and exclusion settings
+ **CustomExtension** iss used to apply a set of common configs such as enabling TLS1.2 for .Net, disabling IE ESC, relaxing UAC

### Management
Once deployed, the VM can be administered thru either of the following:

+ **RDP** is enabled, but can only be used for direct remote management if VM is provisioned with a public IP either during or after deployment
+ **Azure Bastion** basic is also offered as an alternative to managing the VMs via a direct RDP connection

## Deployment
The VM can be deployed through one of two ways:

+ Click the "Deploy to Azure" button to launch the deployment UI in Azure
+ From any computer, execute the powershell "Test-Client_vm.ps1" script located in the 'Resources folder

### Pre-requisites
Prior to deploying the template, have the following ready:

+ Access to an Azure subscription with sufficient resources to deploy the VM
+ An existing Azure VNet & SubNet for deploying the the VM into
+ An existing Active Directory Domain to join the VM to
+ If enabling a public IP, you'll also need to specify a DNS hostname prefix for public FQDN of the VM. The FQDN will be formated as _\<DNS label prefix\>\<VM hostname\>.\<region\>.cloudapp.azure.com_. You'll enter this in the __Dns Label Prefix__ field after clicking the __Deploy to Azure__ button and can be used to connect to the VM directly via RDP

## Additional notes
<details>
  <summary>Expand</summary>

<p><p>
<li> Guest OS configuration is executed using combination of DSC, custom extensions, and thru XConfigs.ps1</li>
<li> A localadmin account is created on the VM, with the same password specified for the domain admin account during deployment
<li> Deployment outputs include VMs public IP address and FQDN, if enabled
<li> The default VM size for the VM in the deployment is Standard_B2s, but can be changed
<li> If the specified VM size is smaller than DS4_v2, the client VM deployment may take longer than expected and may appear to fail. The client VMs and extensions may or may not deploy successfully. This is due to an ongoing Azure client deployment bug, and only happens when the client VM size is smaller than DS4_v2.

</details>
