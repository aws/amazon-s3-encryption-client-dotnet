using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Amazon.Extensions.S3.Encryption.Util;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class EncryptionUtilsV4Tests
    {
        [Fact]
        public void BuildEncInstructionsForV3Object_WithValidKmsKeyLength_ShouldSucceed()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey; // KeyDerivationInputLengthInBits = 256
            var decryptedEnvelopeKeyKms = new byte[32]; // 256 bits = 32 bytes
            var encryptedEnvelopeKey = new byte[16];
            var messageId = new byte[28];
            var keyCommitment = new byte[28];
            
            var result = EncryptionUtils.BuildEncInstructionsForV3Object(
                encryptedEnvelopeKey, messageId, "kms+context", null, null, 
                null, decryptedEnvelopeKeyKms, keyCommitment, algorithmSuit);

            Assert.NotNull(result);
        }

        [Fact]
        public void BuildEncInstructionsForV3Object_WithInvalidKmsKeyLength_ShouldThrowException()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey; // KeyDerivationInputLengthInBits = 256
            var decryptedEnvelopeKeyKms = new byte[16]; // Wrong length: 128 bits instead of 256
            var encryptedEnvelopeKey = new byte[16];
            var messageId = new byte[28];
            var keyCommitment = new byte[28];
            
            var exception = Assert.Throws<AmazonCryptoException>(() =>
                EncryptionUtils.BuildEncInstructionsForV3Object(
                    encryptedEnvelopeKey, messageId, "kms+context", null, null,
                    null, decryptedEnvelopeKeyKms, keyCommitment, algorithmSuit));

            Assert.Contains("The length of decrypted KMS envelope key is 16 bytes", exception.Message);
            Assert.Contains("but the algorithm suite requires 32 bytes", exception.Message);
        }
        
        [Fact]
        public void GetInfoForHkdf_WithValidAlgorithmSuit_ShouldReturnCorrectBytes()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
    
            var result = EncryptionUtils.GetInfoForHkdf(algorithmSuit);
    
            var expected = new byte[] { 0x00, 0x73 }.Concat(Encoding.UTF8.GetBytes("DERIVEKEY")).ToArray();
            Assert.Equal(expected, result);
        }
        
        [Fact]
        public void GetInfoForHkdf_WithValidAlgorithmSuit_ShouldReturnIncorrectBytes()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
    
            var result = EncryptionUtils.GetInfoForHkdf(algorithmSuit);
    
            var expected = new byte[] { 0x00, 0x73 }.Concat(Encoding.UTF8.GetBytes("DummyBytes")).ToArray();
            Assert.NotEqual(expected, result);
        }

        [Fact]
        public void GetInfoForHkdf_WithUnsupportedAlgorithmSuit_ShouldThrowException()
        {
            var algorithmSuit = AlgorithmSuite.AlgAes256CbcIv16NoKdf;
    
            var exception = Assert.Throws<ArgumentException>(() => 
                EncryptionUtils.GetInfoForHkdf(algorithmSuit));
    
            Assert.Contains("does not require HKDF or is not supported", exception.Message);
        }
        
        [Fact]
        public void GetInfoForCommitKey_WithValidAlgorithmSuit_ShouldReturnCorrectBytes()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
    
            var result = EncryptionUtils.GetInfoForCommitKey(algorithmSuit);
    
            var expected = new byte[] { 0x00, 0x73 }.Concat(Encoding.UTF8.GetBytes("COMMITKEY")).ToArray();
            Assert.Equal(expected, result);
        }
        
        [Fact]
        public void GetInfoForCommitKey_WithValidAlgorithmSuit_ShouldReturnIncorrectBytes()
        {
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
            var algorithmSuit = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
    
            var result = EncryptionUtils.GetInfoForCommitKey(algorithmSuit);
    
            var expected = new byte[] { 0x00, 0x73 }.Concat(Encoding.UTF8.GetBytes("DummyBytes")).ToArray();
            Assert.NotEqual(expected, result);
        }

        [Fact]
        public void GetInfoForCommitKey_WithUnsupportedAlgorithmSuit_ShouldThrowException()
        {
            var algorithmSuit = AlgorithmSuite.AlgAes256CbcIv16NoKdf;
    
            var exception = Assert.Throws<ArgumentException>(() => 
                EncryptionUtils.GetInfoForCommitKey(algorithmSuit));
    
            Assert.Contains("does not require key commitment or is not supported.", exception.Message);
        }

    }
}