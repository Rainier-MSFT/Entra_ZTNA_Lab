<p dir='rtl' align='right'>Last updated 21/03/2023</p>

# Entra ZTNA Lab - 3 VM Topology                                                                                                       

**Time to deploy**: Approx. 30 minutes

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="images/deploytoazure.svg"/>
</a>
<a href="https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="images/deploytoazuregov.svg"/>
<a/>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="images/visualizebutton.svg"/>
</a><p>

<a><img src="images/ready3.svg"/></a>
## Azure Resources
The following ARM resources are deployed as part of the solution:

### VMs
+ **AD DC VM**: Windows Server 2016, 2019, or 2022 VM configured as a domain controller with DNS & Certificate services. The Azure AD connect installer shortcut is available on the desktop to setup a sync to an Azure AD tenant, and so is a link to download an Azure AD Application proxy connector
+ **App Server VM**: Windows Server 2016, 2019, or 2022 VM joined to the domain. IIS 10 and .NET 4.5 are installed and several test apps are pre-configured for IWA, forms, and header based authentication. The directory C:\Files containing the file example.txt is shared as "\\APP1\Files" with full control for domain accounts
+ **Client VM**: Optional Windows 10 or 11 client joined to the AD domain

### Storage
+ **Storage account**: Diagnostics storage account, and client VM storage account if indicated. AD DC and App Server VMs in the deployment use managed disks, so no storage accounts are created for VHDs

### Networking
+ **NSG**: Network security group configured to allow inbound RDP on 3389
+ **Virtual network**: Azure VNet for internal traffic, configured as 10.0.0.0/22 and with custom DNS pointing to the AD DC's private IP address. Internnal Subnet is defined as 10.0.0.0/24 for a total of 249 available IP addresses and Bastion subnet as 10.0.1.0/26
+ **Network interfaces**: 1 NIC per VM, all with static private IPs
+ **Public IP addresses**: VMs are only provisioned with an optional static public IP for remote management, if selected during deployment
+ The NSG all in bound connectivity but allows outbound connectivity to the Internet without restrictions

### Extensions
+ Each member VM uses the **JsonADDomainExtension** extension to join the domain post Azure deployment
+ The **BGInfo** extension is applied to all VMs, but will not display over RDP sessions that have the wallpaper disabled
+ The **Antimalware** extension is applied to all VMs with basic scheduled scan and exclusion settings
+ A **CustomExtension** is used to apply a set of common configs to such as enabling TLS1.2 & .Net connectivity, disabling IE ESC, relaxing UAC, and a bunch of extras to help complete the hybrid setup  

### Management
+ **RDP** is enabled on all VMs. Can only be used remotely if machiens were provisioned with a public IP 
+ **Azure Bastion** basic is also offered as an alternative to managing the VMs via a direct RDP connection 

<br>

## Deployment
You can deploy the environment in one of two ways:

+ Click the "Deploy to Azure" button to open the deployment UI in the Azure portal
+ Execute the PowerShell script at https://raw.githubusercontent.com/Rainier-MSFT/Entra_ZTNA_Lab/main/Base-config_3-vm/scripts/Deploy-Base-config_3-vm.ps1 on your local computer

### Pre-requisites
Prior to deploying the template, have the following ready:

+ A DNS label prefix for the URLs of the public IP addresses of your virtual machines. These FQDNs are generated for each virtual machine in your deployment using format _\<DNS label prefix\>\<VM hostname\>.\<region\>.cloudapp.azure.com_. Enter this label in the __Dns Label Prefix__ field after clicking the __Deploy to Azure__ button or for the value of the __dnsLabelPrefix__ variable in the template parameters file

### Client machine
Test clients can be deployed thru either of the following options of options, providing the machine is Hybrid Azure AD joined (HAADJ) or Azure AD Joined (AADJ) to the test Azure AD tenant.   
     
+ Physical computer - On a personal computers, install Windows 10 or 11 Enterprise
+ Virtual machine - Use your prefered hypervisor to create a Windows 10/11 Enterprise VM
+ Virtual machine in Azure - To create a Windows 10/11 virtual machine in Microsoft Azure, you must have a Visual Studio-based subscription, which has access to the images for Windows 10/11 Enterprise. Other types of Azure subscriptions, such as trial and paid subscriptions, do not have access to this image. For the latest information, see Use Windows client in Azure for dev/test scenarios. For more information about eligible subscriptions, see https://docs.microsoft.com/en-us/azure/virtual-machines/windows/client-images#subscription-eligibility.
     
**Note:** Enabling the option to deploy a client VM via this template requires that you upload a generalized Windows 10/11 VHD to an Azure storage account and provide the account name in the _clientVhdUri_ parameter. Note that SAS tokens are not supported, and the blob container must be configured for public read access. The path to the VHD should resemble the following example:

https://<storage account name>.blob.core.windows.net/vhds/<vhdName>.vhd

For more information about how to prepare a generalized VHD, see https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image.
<p><p>
     
<details>
<summary><b><u><font size="+4">Additional Notes</font></u></b></summary>

<p><p>
<li> All guest OS configuration is executed with DSC, using the resources CreateADPDC.ps1.zip and AppConfig.ps1.zip</li>
<li>The domain user *User1* is created in the domain and added to the Domain Admins group. User1's password is the one you provide in the *adminPassword* parameter
<li> The *App server* and *Client* VM resources depend on the **ADDC** resource deployment in order to ensure that the AD domain exists prior to execution of 
the JoinDomain extensions for the member VMs. This asymmetric VM deployment process adds several minutes to the overall deployment time
<li> The private IP address of the **ADDC** VM is always *10.0.0.10*. This IP is set as the DNS IP for the virtual network and all member NICs
<li> The default VM size for all VMs in the deployment is Standard_B2s
<li> Deployment outputs include public IP address and FQDN for each VM
<li> When the specified VM size is smaller than DS4_v2, the client VM deployment may take longer than expected, and then may appear to fail. The client VMs and extensions may or may not deploy successfully. This is due to an ongoing Azure client deployment bug, and only happens when the client VM size is smaller than DS4_v2.

</details>