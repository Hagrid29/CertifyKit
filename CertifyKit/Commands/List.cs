using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Microsoft.Win32;
using CertifyKit.Lib;

namespace CertifyKit.Commands
{
    public class List : ICommand
    {
        public static string CommandName => "list";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: List Certificates");

            StoreLocation storelocation = StoreLocation.CurrentUser;
            StoreName storename = StoreName.My;
            var export = arguments.ContainsKey("/outfile");
            var remove = arguments.ContainsKey("/remove");
            var base64 = arguments.ContainsKey("/base64");
            var install = arguments.ContainsKey("/install");

            if (arguments.ContainsKey("/storelocation"))
            {
                string t = arguments["/storelocation"];
                if(t == "currentuser")
                    storelocation = StoreLocation.CurrentUser;
                if (t == "localmachine")
                    storelocation = StoreLocation.LocalMachine;
            }
            if(arguments.ContainsKey("/storename"))
            {
                string t = arguments["/storename"];
                if (t == "my")
                    storename = StoreName.My;
                if (t == "root")
                    storename = StoreName.Root;
                if (t == "ca")
                    storename = StoreName.CertificateAuthority;
                if (t == "trustedppl")
                    storename = StoreName.TrustedPeople;
                if (t == "trustedpub")
                    storename = StoreName.TrustedPublisher;
                if (t == "addrbook")
                    storename = StoreName.AddressBook;
                if (t == "authroot")
                    storename = StoreName.AuthRoot;
                if (t == "disallowed")
                    storename = StoreName.Disallowed;

            }

            if (arguments.ContainsKey("/certificate"))
            {
                string cert = arguments["/certificate"];
                string password = arguments.ContainsKey("/password") ? arguments["/password"] : "";
                string encpass = arguments.ContainsKey("/encpass") ? arguments["/encpass"] : "";

                //if it is dir
                if (Directory.Exists(cert))
                {
                    Console.WriteLine($"\n[*] Certificate in directory {cert}:\n");
                    string dir = cert;
                    string[] files;
                    if (arguments.ContainsKey("/recurse"))
                        files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
                    else
                        files = Directory.GetFiles(dir, "*");

                    foreach (string file in files)
                    {
                        string[] extlist = { ".pfx", ".p12", ".pkcs12", ".crt", ".cer", ".p7b", ".sst" };
                        string ext = Path.GetExtension(file);
                        foreach (string e in extlist)
                        {
                            if (e == ext.ToLower())
                            {
                                try
                                {
                                    X509Certificate2Collection result = new X509Certificate2Collection();
                                    result.Import(file, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                                    ListUtil.ListCertCollection(result, false, Path.GetFullPath(file), 0, 0);
                                }
                                catch 
                                {
                                    Console.WriteLine($"[X] Failed to read {Path.GetFullPath(file)}\n");
                                }
                            }
                                
                        }
                    }
                }
                //else if it is a file/thumbprint/base64 cert
                else
                {
                    X509Certificate2Collection result = ListUtil.GetCertCollection(cert, password, out string filepathDTO, out StoreName storenameDTO, out StoreLocation storelocationDTO, storename, storelocation);
                    if (arguments.ContainsKey("/chain"))
                    {
                        result = ListUtil.BuildCertChain(result);
                        Console.WriteLine("[*] Built certificate chain");
                    }

                    if (install)
                    {
                        ListUtil.InstallCertCollection(result, storename, storelocation);
                        Console.WriteLine($"\n[*] Certificate installed!");
                    }
                    else if (base64)
                    {
                        string base64Cert = ListUtil.Base64CertCollection(result, encpass);
                        Console.WriteLine($"\n[*] Base64 encoded certificate:\n\r{base64Cert}");
                    }
                    else if (export)
                    {
                        string outfile = arguments["/outfile"];
                        ListUtil.ExportCertCollection(result, outfile, encpass);
                        Console.WriteLine($"\n[*] Export certificate   : {outfile}");

                    }
                    else if (remove && (storenameDTO != 0 || storelocationDTO != 0))
                    {
                        ListUtil.ExportCertFromStore(result, storenameDTO, storelocationDTO);
                        Console.WriteLine($"\n[*] Certificate removed!");
                    }
                    else
                    {
                        Console.WriteLine();
                        ListUtil.ListCertCollection(result, true, filepathDTO, storenameDTO, storelocationDTO);
                    }
                }
                
                
            }
            else if (arguments.ContainsKey("/golden"))
            {
                Console.WriteLine("\n[*] Chain of CA certificate:");
                string paramReg = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\CertSvc\\Configuration";
                string name = (string)Registry.GetValue(paramReg, "Active", "");
                string encpass = arguments.ContainsKey("/encpass") ? arguments["/encpass"] : "";

                X509Certificate2Collection result = ListUtil.FindCertbySubjectName(name, StoreName.My, StoreLocation.LocalMachine, true);
                result = ListUtil.BuildCertChain(result);
                if (export)
                {
                    if (!Elevator.IsHighIntegrity())
                        throw new AccessViolationException("Need to be in an elevated context");
                    string outfile = arguments["/outfile"];
                    ListUtil.ExportCertCollection(result, outfile, encpass);
                    Console.WriteLine($"[*] Exported Certificate   : {outfile}");
                    
                }
                else if (base64)
                {
                    string base64Cert = ListUtil.Base64CertCollection(result, encpass);
                    Console.WriteLine($"[*] Base64 encoded certificate:\n\r{base64Cert}");
                }
                else
                    ListUtil.ListCertCollection(result, true, null, StoreName.My, StoreLocation.LocalMachine);
            }
            else
            {
                Console.WriteLine();
                ListUtil.ListCert(storelocation, storename);
            }


        }
    }
}