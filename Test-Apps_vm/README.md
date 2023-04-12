<p dir='rtl' align='right'>Last updated 21/03/2023</p>

# Entra ZTNA Lab - Test Apps VM                                                                                                       

**Time to deploy**: Approx. 15 minutes

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="https://aka.ms/deploytoazurebutton"/>
</a>
<a href="https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="images/deploytoazuregov.svg"/>
<a/>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FRainier-MSFT%2FEntra_ZTNA_Lab%2Fmain%2FBase-config_3-vm%2Fazuredeploy.json" target="_blank">
<img src="https://github.com/Rainier-MSFT/Entra_ZTNA_Lab/blob/main/Test-Apps_vm/images/visualizebutton.svg"/>
</a><p>

This Azure automation deploys a **Test App VM** that's pre-configured with a mix of services for testing various authentication & authorization scenarios for Zero Trust Network Access (ZTNA) to protected resources. The template provisions a single VM with your prefered version of Windows Server, to an existing Azure VNet. IIS & a bunch of sample Websites configured for various authentication schemes such as Integrated Windows Authentication (IWA), Headers, and Forms. iPerf is also installed for testing network performance, along with an SMB network file share.

## Azure Resources
The following ARM resources are deployed as part of the solution:

+ **App Server VM**: Windows Server 2016, 2019, or 2022 VM joined to the domain. IIS 10 and .NET 4.5 are installed and several test apps are pre-configured for IWA, forms, and header based authentication. The directory C:\Files containing the file example.txt is shared as "\\APP1\Files" with full control for domain accounts
+ **Network interfaces**: 1 NIC per VM
+ **Public IP addresses**: 1 static public IP if chosen during deployment

### Extensions
+ **JoinDomain** is used to join a specified domain
+ **BGInfo** is applied to the VM but will not display over RDP sessions that have the wallpaper disabled
+ **iaaSAntimalware** is applied with basic scheduled scan and exclusion settings
+ A **CustomExtension** is used to apply a set of common configs such as enabling TLS1.2 for .Net, disabling IE ESC, relaxing UAC, and deploying the test services

### Management
Once deployed, the VM can be administered thru either of the following:

+ **RDP** is enabled, but can only be used for direct remote management if VM is provisioned with a public IP either during or after deployment
+ **Azure Bastion** basic is also offered as an alternative to managing the VMs via a direct RDP connection 

**Note:** Don't forget to log into the VM using a domain account. I.e. username@domain

## Deployment
You can deploy the VM in one of two ways:

+ Click the "Deploy to Azure" button to open the deployment UI in the Azure portal
+ Execute the "Test-Apps_vm.ps1" powershell script in the 'Resources folder from any computer

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
<li> Guest OS configuration is executed using DSC & custom extensions thru AppConfig.ps1.zip & Common_Configs.ps1 resources</li>
<li> A *User1* domain account is created and added to the Domain Admins group. The password is the same as provided in the *adminPassword* parameter during deployment
<li> The *App server* and *Client* VM resources depend on the **ADDC** resource deployment in order to ensure that the AD domain exists prior to execution of 
the JoinDomain extensions for the member VMs. This asymmetric VM deployment process adds several extra minutes to the overall deployment time
<li> The private IP address of the **ADDC** VM is always *10.0.0.10*. This IP is set as the DNS IP for the virtual network and all member NICs
<li> Deployment outputs include public IP address and FQDN for each VM
<li> The default VM size for the VM in the deployment is Standard_B2s, but can be changed
<li> When the specified VM size is smaller than DS4_v2, the client VM deployment may take longer than expected, and then may appear to fail. The client VMs and extensions may or may not deploy successfully. This is due to an ongoing Azure client deployment bug, and only happens when the client VM size is smaller than DS4_v2.

</details>
