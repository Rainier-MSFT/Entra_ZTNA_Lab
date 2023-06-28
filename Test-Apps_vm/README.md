<p dir='rtl' align='right'>Last updated 21/03/2023</p>
  
# <img align="left" src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/assets/6311098/47a893d3-e254-4a65-be16-176ae90be6e0" width=8%> Entra ZTNA Lab - Test Apps VM 

**Time to deploy**: Approx. 20 minutes

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Apps_vm%2Fazuredeploy.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton"/>
</a>
<a href="https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Apps_vm%2Fazuredeploy.json" target="_blank">
<img src="images/deploytoazuregov.svg"/>
<a/>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FTest-Apps_vm%2Fazuredeploy.json" target="_blank">
<img src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/images/visualizebutton.svg"/>
</a><p>

This Azure automation deploys a **Test App VM** pre-configured with a mix of services for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources. The template provisions a single VM with your prefered version of Windows Server, to an existing Azure VNet. IIS & a bunch of sample Websites configured for various authentication schemes such as Integrated Windows Authentication (IWA), Headers, and Forms. iPerf is also installed for testing network performance, along with an SMB network file share.

## Azure Resources
The following ARM resources are deployed as part of the solution:

### VMs
+ **App Server VM**: Windows Server 2016, 2019, or 2022 VM that can be joined to any Windows Active Diretory (AD) domain. IIS 10 and .NET 4.5 are installed and several test apps are pre-configured for IWA, forms, and header based authentication. The directory C:\Files containing the file example.txt is shared as "\\APP1\Files" with full control for domain accounts. iPerf is also installed for network performance testing.

### Networking
+ **Network interfaces**: 1 NIC and a prefered private IP address can be specified during deployment 
+ **Public IP addresses**: 1 static public IP if chenabled during deployment

### Extensions
+ **JoinDomain** is used to join a specified domain
+ **BGInfo** displays session info on desktop wallpaper on all VMs, but only displays over direct RDP sessions and not over Azure Bastion
+ **iaaSAntimalware** is applied with basic scheduled scan and exclusion settings
+ **CustomExtension** is used to apply a set of common configs such as enabling TLS1.2 for .Net, disabling IE ESC, relaxing UAC, and deploying the test services

### Management
Once deployed, the VM can be administered thru either of the following:

+ **RDP** is enabled, but can only be used for direct remote management if VM is provisioned with a public IP either during or after deployment
+ **Azure Bastion** basic is also offered as an alternative to managing the VMs via a direct RDP connection 

**Note:** Don't forget to log into the VM using the domain admin account, not the local admin. I.e. <domain_admin>@<your_domain>

## Deployment
You can deploy the VM in one of two ways:

+ Click the "Deploy to Azure" button to open the deployment UI in the Azure portal
+ From any computer, execute the "Test-Apps_vm.ps1" powershell script found in the 'Resources folder

### Pre-requisites
Prior to deploying the template, have the following information ready:

+ Access to an Azure subscription with sufficient resources to deploy the VM
+ A DNS label prefix for the URL of the public IP addresse of your virtual machine. The FQDN will be formated as _\<DNS label prefix\>\<VM hostname\>.\<region\>.cloudapp.azure.com_. You'll enter this in the __Dns Label Prefix__ field after clicking the __Deploy to Azure__ button
+ An existing Azure VNet & SubNet for deploying the the VM into
+ An existing Active Directory Domain to join the VM to

## Additional notes
<details>
  <summary>Expand</summary>

<p><p>
<li> Guest OS configuration is executed using DSC & custom extensions thru AppConfig.ps1.zip & XConfigs.ps1 resources</li>
<li> A localadmin account is created on the VM, with the same password specified for the domain admin account during deployment
<li> Deployment outputs include VMS public IP address and FQDN, if enabled
<li> The default VM size for the VM in the deployment is Standard_B2s, but can be changed
<li> When the specified VM size is smaller than DS4_v2, the client VM deployment may take longer than expected, and then may appear to fail. The client VMs and extensions may or may not deploy successfully. This is due to an ongoing Azure client deployment bug, and only happens when the client VM size is smaller than DS4_v2.

</details>
