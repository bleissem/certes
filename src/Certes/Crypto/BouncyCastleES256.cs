using Certes.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Certes.Crypto
{
    internal class BouncyCastleES256
    {
        private AsymmetricCipherKeyPair keyPair;

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        public SignatureAlgorithm Algorithm => SignatureAlgorithm.ES256;

        public BouncyCastleES256(AsymmetricCipherKeyPair keyPair)
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
            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, keyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            var signature = signer.GenerateSignature();
            return signature;
        }

        public static object CreateKeyPair()
        {
            var keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            keyGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
            var keyPair = keyGen.GenerateKeyPair();
            return keyPair;
        }
    }
}
