using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3.Model;
using Xunit;
using Xunit.Extensions;

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

        [Fact]
        public void UpdateMetadataWithEncryptionInstructionsV3_ShouldAddAllV3Metadata()
        {
            var request = new PutObjectRequest();
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string> { { "key", "value" } },
                new Dictionary<string, string> { { "context", "value" } },
                new byte[32],
                new byte[16],
                "kms+context",
                new byte[28],
                new byte[28],
                AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey);

            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV3(request, instructions);
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=test
            //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
            Assert.NotNull(request.Metadata["x-amz-c"]);
            Assert.NotNull(request.Metadata["x-amz-3"]);
            Assert.NotNull(request.Metadata["x-amz-w"]);
            Assert.NotNull(request.Metadata["x-amz-d"]);
            Assert.NotNull(request.Metadata["x-amz-i"]);
            Assert.NotNull(request.Metadata["x-amz-t"]); // KMS encryption context
            Assert.Null(request.Metadata["x-amz-m"]); // Should not have materials description for KMS
        }

        [Theory]
        [InlineData("RSA-OAEP-SHA1")]
        [InlineData("AES/GCM")]
        public void UpdateMetadataWithEncryptionInstructionsV3_WithNonKmsWrapAlgorithm_ShouldAddMaterialsDescription(
            string wrapAlgorithm)
        {
            var request = new PutObjectRequest();
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string> { { "key", "value" } },
                null,
                new byte[32],
                new byte[16],
                wrapAlgorithm,
                new byte[28],
                new byte[28],
                AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey);

            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV3(request, instructions);
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=test
            //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
            Assert.NotNull(request.Metadata["x-amz-c"]);
            Assert.NotNull(request.Metadata["x-amz-3"]);
            Assert.NotNull(request.Metadata["x-amz-w"]);
            Assert.NotNull(request.Metadata["x-amz-d"]);
            Assert.NotNull(request.Metadata["x-amz-i"]);
            Assert.Null(request.Metadata["x-amz-t"]); 
            Assert.NotNull(request.Metadata["x-amz-m"]);
        }
        
        [Fact]
        public void CreateInstructionFileRequestV3_WithPutObjectRequest_ShouldAddAllV3Metadata()
        {
            var request = new PutObjectRequest { BucketName = "test-bucket", Key = "test-key" };
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string> { { "key", "value" } }, 
                null,
                new byte[32], 
                new byte[16], 
                "kms+context", 
                new byte[28], 
                new byte[28], 
                AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey);

            var result = EncryptionUtils.CreateInstructionFileRequestV3(request, instructions);
            
            Assert.NotNull(result);
            Assert.Equal("test-bucket", result.BucketName);
            Assert.Equal("test-key.instruction", result.Key);

            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=test
            //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
            
            // Verify ALL V3 metadata was added to original request
            Assert.NotNull(request.Metadata["x-amz-c"]);  // ContentCipherV3
            Assert.NotNull(request.Metadata["x-amz-d"]);  // KeyCommitmentV3  
            Assert.NotNull(request.Metadata["x-amz-i"]);  // MessageIdV3
    
            // Verify instruction file contains required V3 keys
            var contentJson = JsonUtils.ToDictionary(result.ContentBody);
            Assert.Contains("x-amz-3", contentJson.Keys);  // EncryptedDataKeyV3
            Assert.Contains("x-amz-w", contentJson.Keys);  // EncryptedDataKeyAlgorithmV3
            Assert.Contains("x-amz-m", contentJson.Keys);  // MatDescV3
        }
    }
}