using System.Security.Cryptography;
using Certes.Jws;
using Certes.Pkcs;

namespace Certes.Crypto
{
#if !NETSTANDARD1_3
    /// <summary>
    /// 
    /// </summary>
    public class DefaultRS256 : IAsymmetricCipherKeyPair
    {
        private RSAParameters keyPair;

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        /// <exception cref="System.NotImplementedException"></exception>
        public SignatureAlgorithm Algorithm => SignatureAlgorithm.RS256;

        /// <summary>
        /// Gets the json web key.
        /// </summary>
        /// <value>
        /// The json web key.
        /// </value>
        public JsonWebKey JsonWebKey
        {
            get
            {
                return new JsonWebKey
                {
                    Exponent = JwsConvert.ToBase64String(keyPair.Exponent),
                    KeyType = "RSA",
                    Modulus = JwsConvert.ToBase64String(keyPair.Modulus)
                };
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BouncyCastleRS256"/> class.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        public DefaultRS256(RSAParameters keyPair)
        {
            this.keyPair = keyPair;
        }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        /// <summary>
        /// Signs the data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] SignData(byte[] data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(keyPair);
                return rsa.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
            }
        }
    }
#endif
}
