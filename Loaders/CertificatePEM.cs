using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;

namespace BoletoHibridoBradesco.Loaders
{
    /// <summary>
    /// Classe de apoio que carrega um certificado a partir de arquivos PEM
    /// </summary>
    public abstract class CertificatePEM
    {
        public static X509Certificate2 LoadCertificateFromPem(string pemFilePath, string privateKeyFilePath = null)
        {
            // Ler o conteúdo do arquivo PEM
            var certPem = File.ReadAllText(pemFilePath);

            // Extrair o certificado
            var cert = ExtractCertificate(certPem);

            if (!string.IsNullOrEmpty(privateKeyFilePath))
            {
                // Ler a chave privada, se fornecida
                var privateKeyPem = File.ReadAllText(privateKeyFilePath);
                var rsa = ExtractPrivateKey(privateKeyPem);
                cert.PrivateKey = rsa;
            }

            return cert;
        }

        private static X509Certificate2 ExtractCertificate(string certPem)
        {
            if (!certPem.Contains("-----BEGIN CERTIFICATE-----"))
                return null;
            if (!certPem.Contains("-----END CERTIFICATE-----"))
                return null;

            var certBody = certPem.Replace("\n", string.Empty).Replace("\r", string.Empty);
            certBody = certBody.Substring(certBody.IndexOf("-----BEGIN CERTIFICATE-----") + "-----BEGIN CERTIFICATE-----".Length);
            certBody = certBody.Substring(0, certBody.IndexOf("-----END CERTIFICATE-----"));

            var certBytes = Convert.FromBase64String(certBody);
            return new X509Certificate2(certBytes);
        }


        private static RSACryptoServiceProvider ExtractPrivateKey(string privateKeyPem)
        {
            if (!privateKeyPem.Contains("-----BEGIN PRIVATE KEY-----"))
                return null;
            if (!privateKeyPem.Contains("-----END PRIVATE KEY-----"))
                return null;

            var keyBody = privateKeyPem;
            keyBody = keyBody.Substring(keyBody.IndexOf("-----BEGIN PRIVATE KEY-----"));
            keyBody = keyBody.Substring(0, keyBody.IndexOf("-----END PRIVATE KEY-----") + "-----END PRIVATE KEY-----".Length);


            // Crie um leitor PEM
            using (StringReader reader = new StringReader(keyBody))
            {
                var pemReader = new PemReader(reader);

                // Leia o certificado
                object pemObject = pemReader.ReadObject();
                var privateKey = (RsaPrivateCrtKeyParameters)pemObject;
                return ConvertToRSACryptoServiceProvider(privateKey);
            }
        }

        static RSACryptoServiceProvider ConvertToRSACryptoServiceProvider(RsaPrivateCrtKeyParameters privateKey)
        {
            RSAParameters rsaParams = new RSAParameters
            {
                Modulus = privateKey.Modulus.ToByteArrayUnsigned(),
                Exponent = privateKey.PublicExponent.ToByteArrayUnsigned(),
                D = privateKey.Exponent.ToByteArrayUnsigned(),
                P = privateKey.P.ToByteArrayUnsigned(),
                Q = privateKey.Q.ToByteArrayUnsigned(),
                DP = privateKey.DP.ToByteArrayUnsigned(),
                DQ = privateKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKey.QInv.ToByteArrayUnsigned()
            };

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParams);
            return rsa;
        }

    }

}