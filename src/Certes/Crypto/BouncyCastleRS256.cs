using Certes.Jws;
using Certes.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Certes.Crypto
{
    /// <summary>
    /// 
    /// </summary>
    internal class BouncyCastleRS256 : IAsymmetricCipherKeyPair
    {
        private AsymmetricCipherKeyPair keyPair;

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        public SignatureAlgorithm Algorithm => SignatureAlgorithm.RS256;

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
                var parameters = (RsaPrivateCrtKeyParameters)keyPair.Private;
                return new JsonWebKey
                {
                    Exponent = JwsConvert.ToBase64String(parameters.PublicExponent.ToByteArrayUnsigned()),
                    KeyType = "RSA",
                    Modulus = JwsConvert.ToBase64String(parameters.Modulus.ToByteArrayUnsigned())
                };
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BouncyCastleRS256"/> class.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        public BouncyCastleRS256(AsymmetricCipherKeyPair keyPair)
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
            var sha256 = new Sha256Digest();
            var hashed = new byte[sha256.GetDigestSize()];

            sha256.BlockUpdate(data, 0, data.Length);
            sha256.DoFinal(hashed, 0);

            return hashed;
        }

        /// <summary>
        /// Signs the data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public byte[] SignData(byte[] data)
        {
            var signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            var signature = signer.GenerateSignature();
            return signature;
        }

        public static object CreateKeyPair()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("RSA");
            var generatorParams = new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 128);
            generator.Init(generatorParams);
            var keyPair = generator.GenerateKeyPair();
            return keyPair;
        }
    }
}
