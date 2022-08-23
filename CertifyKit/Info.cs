using System;

namespace CertifyKit
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine("CertifyKit (Hagrid29 version of Certify)");
            Console.WriteLine("More info: https://github.com/Hagrid29/CertifyKit/\n");
        }

        public static void ShowUsage()
        {
            var usage = @"
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

    CertifyKit list /golden [/outfile:C:\backup.pfx | /base64] [/encpass:ENC_PASSWORD]


  Create or remove a machine account:

    CertifyKit account /machine:MACHINE [/createpc | /removepc] [/domain:domain.local | /ldapserver:server.domain.local]

  Alter dNSHostName of a machine account or alter userPrincipalName of a user/machine account or clear userPrincipalName of a user account:

    CertifyKit account [/machine:MACHINE | /user:USER] [/dns:new.domain.local | /upn:new@domain.local] [clear]

  Alter or query attribute of an account:

    CertifyKit account [/machine:MACHINE | /user:USER] /attribute:ATTRIBUTE [/query | /value:VALUE | /clear | /remove:ID] [/append]


  Shadow credentail attack on a machine account and output self signed certificate as base64 string by default:

    CertifyKit account /machine:MACHINE /shadow [/outfile:C:\xxx.pfx | /install] [/encpass:ENC_PASSWORD]

  Query or Remove or clear KeyCredentialLink on a user account:

    CertifyKit account /user:USER /shadow [/list | /remove:ID | /clear]


  Map a certificate to a machine account for the purpose of authentication:

    CertifyKit account /machine:MACHINE /altsecid /certificate:THUMBPRINT/FILE/BASE64 [/password:CERT_PASSWORD]

  Query or Remove or clear altSecurityIdentities on a user account:

    CertifyKit account /user:USER /altsecid [/list | /remove:ID | /clear]
";
            Console.WriteLine(usage);
        }
    }
}
