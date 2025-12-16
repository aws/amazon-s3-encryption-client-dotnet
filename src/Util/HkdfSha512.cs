using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal class HkdfSha512
    {
        internal static byte[] ForAes(byte[] ikm, byte[] salt, byte[] info, int encryptionKeyLengthBytes)
        {
            return DeriveKey(ikm, salt, info, encryptionKeyLengthBytes);
        }
        
        internal static byte[] ForCommitment(byte[] ikm, byte[] salt, byte[] info, int commitKeyLength)
        {
            return DeriveKey(ikm, salt, info, commitKeyLength);
        }
        
        private static byte[] DeriveKey(byte[] ikm, byte[] salt, byte[] info, int keyLength)
        {
            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(ikm, salt, info));
    
            var key = new byte[keyLength];
            // The extract step output (pseudorandom key) is used automatically as input to the expand step when GenerateBytes() is called.
            
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# - The DEK input pseudorandom key MUST be the output from the extract step.
            
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# - The CK input pseudorandom key MUST be the output from the extract step.
            hkdf.GenerateBytes(key, 0, key.Length);
            return key;
        }
    }
}