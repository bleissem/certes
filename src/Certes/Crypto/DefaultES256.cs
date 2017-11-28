#if !NETSTANDARD1_3 && !NET45
using Certes.Jws;
using Certes.Pkcs;
using System.Security.Cryptography;

namespace Certes.Crypto
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="Certes.Crypto.IAsymmetricCipherKeyPair" />
    internal class DefaultES256 : IAsymmetricCipherKeyPair
    {
        private ECParameters parameters;

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        public SignatureAlgorithm Algorithm => SignatureAlgorithm.ES256;

        /// <summary>
        /// Gets the json web key.
        /// </summary>
        /// <value>
        /// The json web key.
        /// </value>
        public object JsonWebKey
        {
            get
            {
                return new
                {
                    kty = "EC",
                    crv = "P-256",
                    x = JwsConvert.ToBase64String(parameters.Q.X),
                    y = JwsConvert.ToBase64String(parameters.Q.Y),
                };
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultES256"/> class.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        public DefaultES256(ECParameters parameters)
        {
            this.parameters = parameters;
        }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
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
        /// <exception cref="System.NotImplementedException"></exception>
        public byte[] SignData(byte[] data)
        {
            using (var ecdsa = ECDsa.Create(this.parameters))
            {
                return ecdsa.SignData(data, HashAlgorithmName.SHA256);
            }
        }
    }
}
#endif
