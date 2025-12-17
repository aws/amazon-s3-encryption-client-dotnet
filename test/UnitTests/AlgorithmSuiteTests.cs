using Amazon.Extensions.S3.Encryption.Util;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AlgorithmSuiteTests
    {
        [Fact]
        public void AlgAes256CbcIv16NoKdf_ShouldHaveCorrectProperties()
        {
            var suite = AlgorithmSuite.AlgAes256CbcIv16NoKdf;
            
            Assert.Equal(AlgorithmSuiteId.AlgAes256CbcIv16NoKdf, suite.Id);
            Assert.Equal(MessageFormatVersion.V1, suite.MessageFormatVersion);
            Assert.Null(suite.AlgorithmSuiteDataLengthInBytes);
            Assert.Equal(256, suite.KeyDerivationInputLengthInBits);
            Assert.Equal(KeyDerivationAlgorithm.Identity, suite.KeyDerivationAlgorithm);
            Assert.Equal(KdfHashFunction.None, suite.KdfHashFunction);
            Assert.Equal(0, suite.SaltLengthInBits);
            Assert.False(suite.KeyCommitment);
            Assert.Equal(EncryptionAlgorithm.AES, suite.EncryptionAlgorithm);
            Assert.Equal(EncryptionMode.CBC, suite.EncryptionMode);
            Assert.Equal(256, suite.EncryptionKeyLengthInBits);
            Assert.Equal(16, suite.IvLengthInBytes);
            Assert.Null(suite.AuthenticationTagLengthInBytes);
            Assert.Null(suite.KeyDerivationOutputLengthInBits);
            Assert.Equal(new byte[] { 0x00, 0x70 }, suite.AlgorithmSuiteIdBytes);
        }

        [Fact]
        public void AlgAes256GcmIv12Tag16NoKdf_ShouldHaveCorrectProperties()
        {
            var suite = AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf;
            
            Assert.Equal(AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf, suite.Id);
            Assert.Equal(MessageFormatVersion.V2, suite.MessageFormatVersion);
            Assert.Null(suite.AlgorithmSuiteDataLengthInBytes);
            Assert.Equal(256, suite.KeyDerivationInputLengthInBits);
            Assert.Equal(KeyDerivationAlgorithm.Identity, suite.KeyDerivationAlgorithm);
            Assert.Equal(KdfHashFunction.None, suite.KdfHashFunction);
            Assert.Equal(0, suite.SaltLengthInBits);
            Assert.False(suite.KeyCommitment);
            Assert.Equal(EncryptionAlgorithm.AES, suite.EncryptionAlgorithm);
            Assert.Equal(EncryptionMode.GCM, suite.EncryptionMode);
            Assert.Equal(256, suite.EncryptionKeyLengthInBits);
            Assert.Equal(12, suite.IvLengthInBytes);
            Assert.Equal(16, suite.AuthenticationTagLengthInBytes);
            Assert.Null(suite.KeyDerivationOutputLengthInBits);
            Assert.Equal(new byte[] { 0x00, 0x72 }, suite.AlgorithmSuiteIdBytes);
        }

        [Fact]
        public void AlgAes256GcmHkdfSha512CommitKey_ShouldHaveCorrectProperties()
        {
            var suite = AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
            
            Assert.Equal(AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey, suite.Id);
            Assert.Equal(MessageFormatVersion.V3, suite.MessageFormatVersion);
            Assert.Equal(28, suite.AlgorithmSuiteDataLengthInBytes);
            Assert.Equal(256, suite.KeyDerivationInputLengthInBits);
            Assert.Equal(KeyDerivationAlgorithm.HKDF, suite.KeyDerivationAlgorithm);
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=test
            //# - The hash function MUST be specified by the algorithm suite commitment settings.
            // When using AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey, Hash function must be KdfHashFunction.SHA512
            Assert.Equal(KdfHashFunction.SHA512, suite.KdfHashFunction);
            Assert.Equal(224, suite.SaltLengthInBits);
            Assert.True(suite.KeyCommitment);
            Assert.Equal(EncryptionAlgorithm.AES, suite.EncryptionAlgorithm);
            Assert.Equal(EncryptionMode.GCM, suite.EncryptionMode);
            Assert.Equal(256, suite.EncryptionKeyLengthInBits);
            Assert.Equal(12, suite.IvLengthInBytes);
            Assert.Equal(16, suite.AuthenticationTagLengthInBytes);
            Assert.Equal(224, suite.KeyDerivationOutputLengthInBits);
            Assert.Equal(new byte[] { 0x00, 0x73 }, suite.AlgorithmSuiteIdBytes);
        }

        [Fact]
        public void GetAlgorithmSuit_ShouldReturnCorrectInstances()
        {
            Assert.Same(AlgorithmSuite.AlgAes256CbcIv16NoKdf, 
                AlgorithmSuite.GetAlgorithmSuit(AlgorithmSuiteId.AlgAes256CbcIv16NoKdf));
            Assert.Same(AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf, 
                AlgorithmSuite.GetAlgorithmSuit(AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf));
            Assert.Same(AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey, 
                AlgorithmSuite.GetAlgorithmSuit(AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey));
        }
    }
}