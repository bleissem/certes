using Certes.Jws;
using Certes.Pkcs;

namespace Certes.Crypto
{
    /// <summary>
    /// 
    /// </summary>
    public interface IAsymmetricCipherKeyPair
    {
        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        SignatureAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the json web key.
        /// </summary>
        /// <value>
        /// The json web key.
        /// </value>
        object JsonWebKey { get; }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// Signs the data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        byte[] SignData(byte[] data);
    }
}
