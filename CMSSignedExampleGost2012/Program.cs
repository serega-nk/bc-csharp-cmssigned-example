using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace CMSSignedExampleGost2012
{
    class Program
    {
        static byte[] SignDetached(byte[] data, X509Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            CmsProcessable msg = new CmsProcessableByteArray(data);
            
            CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            
            gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().Build(
                new Asn1SignatureFactory("GOST3411-2012-256WITHGOST3410-2012-256", privateKey), certificate));

            var certs = new List<X509Certificate> {certificate};
            var storeParams = new X509CollectionStoreParameters(certs);
            var certStore = X509StoreFactory.Create("Certificate/Collection", storeParams);

            gen.AddCertificates(certStore);
            
            CmsSignedData signedData = gen.Generate(msg);
            
            var signature = signedData.GetEncoded();

            return signature;
        }
        
        static bool Verify(byte[] data, byte[] signature, X509Certificate certificate)
        {
            CmsProcessable msg = new CmsProcessableByteArray(data);

            CmsSignedData signedData = new CmsSignedData(msg, signature);

            bool result = false;
            
            foreach (SignerInformation signer in signedData.GetSignerInfos().GetSigners())
            {
                result = signer.Verify(certificate);
                if (!result)
                {
                    break;
                }
            }

            return result;
        }

        static void Main(string[] args)
        {
            var exePath = AppDomain.CurrentDomain.BaseDirectory ?? "";
            
            var crtFilename = Path.Combine(exePath, "data\\test.crt");
            var keyFilename = Path.Combine(exePath, "data\\test.key");
            
            var signerCert = (X509Certificate) new PemReader(File.OpenText(crtFilename)).ReadObject();
            var privateKey = (AsymmetricKeyParameter) new PemReader(File.OpenText(keyFilename)).ReadObject();
            
            String content = "<xml></xml>";
            
            byte[] data = Encoding.UTF8.GetBytes(content);

            var signature = SignDetached(data, signerCert, privateKey);

            Console.Out.WriteLine("content = " + Convert.ToBase64String(data));
            Console.Out.WriteLine("signature = " + Convert.ToBase64String(signature));
            
            // проверка
            Console.Out.WriteLine("Verify = " + Verify(data, signature, signerCert));
        }
    }
}