using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Microsoft.Win32;

namespace CertifyKit.Lib
{

    public class CertificateDTO
    {
        public StoreLocation StoreLocation { get; set; }
        public StoreName StoreName { get; set; }
        public string FilePath { get; set; }
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public DateTime ValidDate { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool HasPrivateKey { get; set; }
        public bool KeyExportable { get; set; }
        public string Thumbprint { get; set; }
        public string Template { get; set; }
        public string SerialNumber { get; set; }
        public List<string> EnhancedKeyUsages { get; set; }
        public string SubAltName { get; set; }

        public void PrintCert(bool detail)
        {
            if (StoreName != 0 && StoreName != 0)
                Console.WriteLine("  Location           : {0}, {1}", StoreName, StoreLocation);
            if (FilePath != null)
                Console.WriteLine("  Location           : {0}", FilePath);
            Console.WriteLine("  Issuer             : {0}", Issuer);
            if (detail)
            {
                Console.WriteLine("  Subject            : {0}", Subject);
                Console.WriteLine("  ValidDate          : {0}", ValidDate);
                Console.WriteLine("  ExpiryDate         : {0}", ExpiryDate);
            }
            Console.WriteLine("  HasPrivateKey      : {0}", HasPrivateKey);
            Console.WriteLine("  KeyExportable      : {0}", KeyExportable);
            Console.WriteLine("  Thumbprint         : {0}", Thumbprint);
            if (detail)
            {
                Console.WriteLine("  Serial Number      : {0}", SerialNumber);
                if (!string.IsNullOrEmpty(Template))
                {
                    Console.WriteLine("  Template           : {0}", Template);
                }
            }
                
            if (EnhancedKeyUsages.Count > 0)
            {
                bool forAuth = false;
                Console.WriteLine("  EnhancedKeyUsages  :");
                foreach (var eku in EnhancedKeyUsages)
                {

                    if (eku == "Client Authentication" || eku == "Smart Card Logon" || eku == "Any Purpose" || eku == "PKINIT Client Authentication")
                    {
                        forAuth = true;
                    }
                    Console.WriteLine("       {0}{1}",
                        eku,
                        forAuth ? "     [!] Certificate can be used for client authentication!" : "");
                }
            }
            else
            {
                Console.WriteLine("  EnhancedKeyUsages  : <null>      [!] Certificate can be used for client authentication!");
            }
            Console.WriteLine("  SubjectAltName     : \n\t{0}", SubAltName);
            Console.WriteLine();
        }
    }

    class ListUtil
    {

        public static CertificateDTO GetCertDTO(X509Certificate2 certificate)
        {

            var template = "";
            var enhancedKeyUsages = new List<string>();
            bool keyExportable = false;

            try
            {
                certificate.PrivateKey.ToXmlString(true);
                keyExportable = true;
            }
            catch (Exception e)
            {
                keyExportable = !e.Message.Contains("not valid for use in specified state");
            }

            foreach (var ext in certificate.Extensions)
            {
                if (ext.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    var extUsages = ((X509EnhancedKeyUsageExtension)ext).EnhancedKeyUsages;

                    if (extUsages.Count == 0)
                        continue;

                    foreach (var extUsage in extUsages)
                    {
                        enhancedKeyUsages.Add(extUsage.FriendlyName);
                    }
                }
                else if (ext.Oid.FriendlyName == "Certificate Template Name" || ext.Oid.FriendlyName == "Certificate Template Information")
                {
                    template = ext.Format(false);
                }
            }

            string tempSAN = "";
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid.FriendlyName == "Subject Alternative Name")
                {
                    tempSAN += extension.Format(true) + "\n";
                }
            }

            return new CertificateDTO()
            {
                Issuer = certificate.Issuer,
                Subject = certificate.Subject,
                ValidDate = certificate.NotBefore,
                ExpiryDate = certificate.NotAfter,
                HasPrivateKey = certificate.HasPrivateKey,
                KeyExportable = keyExportable,
                Template = template,
                Thumbprint = certificate.Thumbprint,
                EnhancedKeyUsages = enhancedKeyUsages,
                SerialNumber = certificate.SerialNumber,
                SubAltName = tempSAN
            };
        }

        public static void ListCert(StoreLocation storeLocation, StoreName storeName)
        {

            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            foreach (var certificate in store.Certificates)
            {
                var result = GetCertDTO(certificate);
                result.StoreLocation = storeLocation;
                result.StoreName = storeName;
                bool forAuth = false;
                if (result.EnhancedKeyUsages.Count > 0)
                    foreach (var eku in result.EnhancedKeyUsages)
                    {
                        if (eku == "Client Authentication" || eku == "Smart Card Logon" || eku == "Any Purpose" || eku == "PKINIT Client Authentication")
                            forAuth = true;
                    }
                else
                    forAuth = true;

                result.PrintCert(false);
            }

        }

        public static void ListCertCollection(X509Certificate2Collection certs, bool detail, string filepath, StoreName storename, StoreLocation storelocation)
        {
            try
            {
                foreach (var tcertificate in certs)
                {
                    var tresult = GetCertDTO(tcertificate);
                    if (filepath != null)
                        tresult.FilePath = filepath;
                    if (storename != 0)
                        tresult.StoreName = storename;
                    if (storelocation != 0)
                        tresult.StoreLocation = storelocation;
                    
                    tresult.PrintCert(detail);
                }
            }
            catch { }
        }

        public static X509Certificate2Collection FindCertbyThumbprint(string Thumbprint, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser, bool validOnly = false)
        {
            X509Store store = new X509Store(storename, storelocation);
            store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCerts = store.Certificates;
            X509Certificate2Collection certs = storeCerts.Find(X509FindType.FindByThumbprint, Thumbprint, validOnly);
            store.Close();
            storeCerts.Clear();
            return certs;
        }
        public static X509Certificate2Collection FindCertbySubjectName(string SubjectName, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser, bool validOnly = false)
        {
            X509Store store = new X509Store(storename, storelocation);
            store.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection storeCerts = store.Certificates;
            store.Close();
            X509Certificate2Collection certs = storeCerts.Find(X509FindType.FindBySubjectName, SubjectName, validOnly);
            storeCerts.Clear();
            return certs;
        }

        public static X509Certificate2Collection BuildCertChain(X509Certificate2Collection certs)
        {
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            X509Certificate2Collection tempcert = new X509Certificate2Collection();
            foreach (X509Certificate2 cert in certs)
            {
                chain.Build(cert);
                if (chain.ChainElements.Count > 0)
                {
                    //start from n=1 to prevent the first duplicated cert
                    for (int n = 1; n < chain.ChainElements.Count; n++)
                    {
                        tempcert.Add(chain.ChainElements[n].Certificate);
                    }
                }
                chain.Reset();
            }
            if (tempcert.Count > 0)
                certs.AddRange(tempcert);

            tempcert.Clear();

            return certs;
        }

       
        public static void ExportCert(X509Certificate2 certs, string filename, string password = "")
        {
            File.WriteAllBytes(filename, certs.Export(X509ContentType.Pfx, password));
        }
        public static void ExportCertCollection(X509Certificate2Collection certs, string filename, string encpass = "")
        {
            File.WriteAllBytes(filename, certs.Export(X509ContentType.Pfx, encpass));
            certs.Clear();
        }
        public static string Base64Cert(X509Certificate2 certs, string password = "")
        {
            byte[] certBytes = certs.Export(X509ContentType.Pfx, password);
            string certOutput = Convert.ToBase64String(certBytes);
            return certOutput;
        }
        public static string Base64CertCollection(X509Certificate2Collection certs, string encpass = "")
        {
            byte[] certBytes = certs.Export(X509ContentType.Pfx, encpass);
            string certOutput = Convert.ToBase64String(certBytes);
            return certOutput;
        }
        public static X509Certificate2Collection GetBase64CertCollection(string base64cert, string password = "")
        {
            byte[] cert = Convert.FromBase64String(base64cert);
            X509Certificate2Collection result = new X509Certificate2Collection();
            result.Import(cert, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            return result;
        }
        public static void InstallCert(X509Certificate2 certs, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser)
        {
            X509Store store = new X509Store(storename, storelocation);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certs);
            store.Close();
        }
        public static void ExportCertFromStore(X509Certificate2Collection certs, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser)
        {
            X509Store store = new X509Store(storename, storelocation);
            store.Open(OpenFlags.ReadWrite);
            store.RemoveRange(certs);
            store.Close();
        }
        public static void InstallCertCollection(X509Certificate2Collection result, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser)
        {
            foreach (X509Certificate2 cert in result)
            {
                ListUtil.InstallCert(cert, storename, storelocation);
            }
        }

        public static X509Certificate2Collection GetCertCollection(string cert, string password, out string filepathDTO, out StoreName storenameDTO, out StoreLocation storelocationDTO, StoreName storename = StoreName.My, StoreLocation storelocation = StoreLocation.CurrentUser)
        {
            filepathDTO = null;
            storenameDTO = 0;
            storelocationDTO = 0;
            X509Certificate2Collection result = new X509Certificate2Collection();
            // if file exist
            if (File.Exists(cert))
            {
                result.Import(cert, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                filepathDTO = Path.GetFullPath(cert);
            }
            // assume its base64 string for string with logn length
            else if (cert.Length > 512)
            {
                result = ListUtil.GetBase64CertCollection(cert, password);
            }
            // else it is thumbprint
            else
            {
                result = FindCertbyThumbprint(cert, storename, storelocation);
                storenameDTO = storename;
                storelocationDTO = storelocation;
            }

            if (result.Count == 0)
                throw new Exception($"Could not find file or thumbprint '{cert}'");

            return result;
        }

        public static string GenCertAltSecId(string cert, string password)
        {
            X509Certificate2Collection result = GetCertCollection(cert, password, out string t1, out StoreName t2, out StoreLocation t3);

            foreach (var tcertificate in result)
            {
                var tresult = GetCertDTO(tcertificate);

                string[] issuer = tresult.Issuer.Split(',');
                string[] subject = tresult.Subject.Split(',');
                string altsecid = "X509:<I>";
                for (int i = issuer.Length - 1; i > -1; i--)
                {
                    altsecid += issuer[i].Trim() + ",";
                }
                altsecid = altsecid.TrimEnd(',');
                altsecid += "<S>";
                for (int i = subject.Length - 1; i > -1; i--)
                {
                    altsecid += subject[i].Trim() + ",";
                }
                altsecid = altsecid.TrimEnd(',');
                return altsecid;
            }
           
            return null;
        }

    }
}
