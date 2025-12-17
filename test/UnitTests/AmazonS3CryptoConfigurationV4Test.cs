using System;
using Xunit;
using Xunit.Extensions;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AmazonS3CryptoConfigurationV4Test
    {
        [Theory]
        [InlineData(SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        //= ../specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        [InlineData(SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        //= ../specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        [InlineData(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        public void Constructor_ValidConfigurations_ShouldSucceed(SecurityProfile securityProfile, CommitmentPolicy commitmentPolicy, ContentEncryptionAlgorithm contentEncryptionAlgorithm)
        {
            var config = new AmazonS3CryptoConfigurationV4(securityProfile, commitmentPolicy, contentEncryptionAlgorithm);
    
            Assert.Equal(commitmentPolicy, config.CommitmentPolicy);
            Assert.Equal(contentEncryptionAlgorithm, config.ContentEncryptionAlgorithm);
        }

        [Theory]
        //= ../specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
        [InlineData(SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        [InlineData(SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        [InlineData(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)]
        [InlineData(SecurityProfile.V4AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)]
        public void Constructor_InvalidConfigurations_ShouldThrowArgumentException(SecurityProfile securityProfile, CommitmentPolicy commitmentPolicy, ContentEncryptionAlgorithm contentEncryptionAlgorithm)
        {
            Assert.Throws<ArgumentException>(() => new AmazonS3CryptoConfigurationV4(securityProfile, commitmentPolicy, contentEncryptionAlgorithm));
        }

    }
}