using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using DotNetUtilities = ThirdParty.Org.BouncyCastle.Security.DotNetUtilities;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal static class RsaUtils
    {
        /// <summary>
        /// Creates Bouncy castle cipher using the .NET implementation of RSA
        /// </summary>
        /// <param name="forEncryption">forEncryption if true the cipher is initialised for encryption, if false for decryption</param>
        /// <param name="rsa">.NET implementation of RSA symmetric algorithm</param>
        /// <returns></returns>
        internal static IBufferedCipher CreateRsaOaepSha1Cipher(bool forEncryption, RSA rsa)
        {
            var cipher = CipherUtilities.GetCipher("RSA/NONE/OAEPPadding");
            if (forEncryption)
            {
                var rsaPublicKey = DotNetUtilities.GetRsaPublicKey(rsa);
                cipher.Init(true, rsaPublicKey);
            }
            else
            {
                var asymmetricCipherKeyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                cipher.Init(false, asymmetricCipherKeyPair.Private);
            }

            return cipher;
        }
    }
}
