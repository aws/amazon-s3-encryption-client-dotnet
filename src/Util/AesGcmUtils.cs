using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Amazon.Extensions.S3.Encryption.Util
{
    /// <summary>
    /// Container of utilities methods for AES GCM encryption/decryption
    /// </summary>
    internal static class AesGcmUtils
    {
        /// <summary>
        /// Create a buffered cipher to encrypt or decrypt a stream as it is being read
        /// </summary>
        /// <param name="forEncryption">forEncryption if true the cipher is initialised for encryption, if false for decryption</param>
        /// <param name="key">Key to be used for encryption</param>
        /// <param name="nonce">Nonce to be used for encryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="associatedText">Additional associated data</param>
        /// <returns></returns>
        internal static IBufferedCipher CreateCipher(bool forEncryption, byte[] key, int tagSize, byte[] nonce, byte[] associatedText)
        {
            var aesEngine = new AesEngine();
            var blockCipher = new GcmBlockCipher(aesEngine);
            var aeadBlockCipher = new BufferedAeadBlockCipher(blockCipher);
            var parameters = new AeadParameters(new KeyParameter(key), tagSize, nonce, associatedText);
            aeadBlockCipher.Init(forEncryption, parameters);
            return aeadBlockCipher;
        }
    }
}