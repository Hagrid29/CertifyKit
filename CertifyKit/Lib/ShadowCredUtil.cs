using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Reflection;
using DSInternals.Common.Data;
using System.DirectoryServices;

namespace CertifyKit.Lib
{
    internal class ShadowCredUtil
    {

        public static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            RSA rsa = new RSACryptoServiceProvider(2048, new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString()));
            CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        public static KeyCredential GenerateKeyCredential(X509Certificate2 cert, string cn, string domain, string domainController)
        {

            DirectoryEntry targetObject = AccountUtil.LocateAccount(cn, domain, domainController);
            Guid guid = Guid.NewGuid();
            KeyCredential keyCredential = new KeyCredential(cert, guid, targetObject.Properties["distinguishedName"][0].ToString(), DateTime.Now);
            
            return keyCredential;
        }

       
        public static void DecodeDnWithBinary(object dnWithBinary, out byte[] binaryValue, out string dnString)
        {
            System.Type type = dnWithBinary.GetType();

            binaryValue = (byte[])type.InvokeMember(
            "BinaryValue",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );

            dnString = (string)type.InvokeMember(
            "DNString",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );
        }
    }
}
