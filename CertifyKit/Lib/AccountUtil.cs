using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Security.AccessControl;
using System.DirectoryServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Threading;
using System.DirectoryServices.Protocols;

using DSInternals.Common.Data;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertifyKit.Lib
{
    class AccountUtil
    {
        private static DirectoryEntry GetLdapSearchRoot(string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (directoryObject != null)
            {
                directoryObject.AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing;
            }

            return directoryObject;
        }
        public static DirectoryEntry LocateAccount(string account, string domain, string domainController)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;

            try
            {
                directoryObject = GetLdapSearchRoot("", domainController, domain);
                userSearcher = new DirectorySearcher(directoryObject);
                userSearcher.PageSize = 1;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.Message);
                }
                return null;
            }

            // check to ensure that the bind worked correctly
            try
            {
                string dirPath = directoryObject.Path;
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("\r\n[X] Error validating the domain searcher: {0}", ex.Message);
                return null;
            }

            try
            {
                string userSearchFilter = String.Format("(samAccountName={0})", account);
                userSearcher.Filter = userSearchFilter;
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return null;
            }

            try
            {
                SearchResult user = userSearcher.FindOne();

                if (user == null)
                {
                    Console.WriteLine("[!] Target user not found");
                }

                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                return user.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.Message);
                }
                return null;
            }
        }


        public static void NewMachineAccount(string domain, string domainController, string machineAccount, string machinePassword)
        {
            string samAccountName;

            if (machineAccount.EndsWith("$"))
            {
                samAccountName = machineAccount;
                machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
            }
            else
            {
                samAccountName = String.Concat(machineAccount, "$");
            }

            byte[] unicodePwd;
            

            domain = domain.ToLower();
            string dnsHostname = String.Concat(machineAccount, ".", domain);
            string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname), String.Concat("RestrictedKrbHost/", dnsHostname), String.Concat("HOST/", machineAccount), String.Concat("RestrictedKrbHost/", machineAccount) };
            unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));
            string distinguishedName = String.Concat("CN=", machineAccount, ",", "CN=Computers");
            string[] domainComponent = domain.Split('.');
            foreach (string dc in domainComponent)
            {
                distinguishedName += String.Concat(",DC=", dc);
            }

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection connection = new LdapConnection(identifier);

            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                connection.SendRequest(request);
                connection.Dispose();
            }
            catch (Exception ex)
            {

                if (ex.Message.Contains("The object exists."))
                {
                    Console.WriteLine("[X] Machine account {0} already exists", machineAccount);
                }
                else if (ex.Message.Contains("The server cannot handle directory requests."))
                {
                    Console.WriteLine("[X] User may have reached ms-DS-MachineAccountQuota limit");
                }
                else
                {
                    Console.WriteLine("[X] Machine account may be already exists in AD environment");
                }

                Console.WriteLine(ex.ToString());
                connection.Dispose();
                throw;
            }

        }


        public static void RemoveMachineAccount(string domain, string domainController, string machineAccount)
        {
            DirectoryEntry directoryEntry = LocateAccount(machineAccount, domain, domainController);

            try
            {
                directoryEntry.DeleteTree();
                directoryEntry.CommitChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static PropertyValueCollection GetAccountAttribute(string domain, string domainController, string attribute, string account)
        {
            DirectoryEntry directoryEntry = LocateAccount(account, domain, domainController);
            
            try
            {
                PropertyValueCollection value = directoryEntry.Properties[attribute];
                return value;
                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void PrintAttribute(string domain, string domainController, string attribute, string account)
        {
            PropertyValueCollection value = AccountUtil.GetAccountAttribute(domain, domainController, attribute, account);
            if (value.Count == 1 && attribute != "altSecurityIdentities" && attribute != "msDS-KeyCredentialLink")
                Console.WriteLine($"  {attribute} :\t\t{value[0]}");
            else
            {
                Console.WriteLine($"  {attribute} :");
                int i = 0;
                foreach (object val in value)
                {
                    if(attribute == "msDS-KeyCredentialLink")
                    {
                        byte[] binaryValue = null;
                        string dnString = null;
                        ShadowCredUtil.DecodeDnWithBinary(val, out binaryValue, out dnString);
                        KeyCredential kc = new KeyCredential(binaryValue, dnString);
                        Console.WriteLine($"    [{i}]\t:   DeviceID: {kc.DeviceId} | Creation Time: {kc.CreationTime}");
                    }
                    else
                        Console.WriteLine($"    [{i}]\t:   {val}");
                    i++;
                }
            }
        }

        public static void SetAccountAttribute(string domain, string domainController, string attribute, string account, string value, string action = "", int rmID = 0)
        {
            DirectoryEntry directoryEntry = LocateAccount(account, domain, domainController);
            
            try
            {
                if (action == "append")
                    directoryEntry.Properties[attribute].Add(value);
                else if (action == "clear")
                    directoryEntry.Properties[attribute].Clear();
                else if(action == "remove")
                    directoryEntry.Properties[attribute].RemoveAt(rmID);
                else
                    directoryEntry.InvokeSet(attribute, value);
                
                directoryEntry.CommitChanges();
                Console.WriteLine("\n[*] Account {0} attribute {1} updated", account, attribute);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

    }
}
