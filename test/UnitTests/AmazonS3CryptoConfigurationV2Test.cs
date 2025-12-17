using System;
using Xunit;
using Xunit.Extensions;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AmazonS3CryptoConfigurationV2Test
    {
        [Fact]
        public void Constructor_WithSecurityProfile_SetsDefaultValues()
        {
#pragma warning disable 0618
            var config = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618
            Assert.Equal(SecurityProfile.V2, config.SecurityProfile);
            Assert.Equal(ContentEncryptionAlgorithm.AesGcm, config.ContentEncryptionAlgorithm);
            Assert.Equal(CommitmentPolicy.ForbidEncryptAllowDecrypt, config.CommitmentPolicy);
        }

        [Fact]
        public void Constructor_WithAllParameters_SetsValues()
        {
            var config = new AmazonS3CryptoConfigurationV2(
                SecurityProfile.V2AndLegacy, 
                CommitmentPolicy.ForbidEncryptAllowDecrypt, 
                ContentEncryptionAlgorithm.AesGcm);

            Assert.Equal(SecurityProfile.V2AndLegacy, config.SecurityProfile);
            Assert.Equal(CommitmentPolicy.ForbidEncryptAllowDecrypt, config.CommitmentPolicy);
            Assert.Equal(ContentEncryptionAlgorithm.AesGcm, config.ContentEncryptionAlgorithm);
        }

        [Fact]
        public void ContentEncryptionAlgorithm_SetAesGcmWithCommitment_ThrowsNotSupportedException()
        {
#pragma warning disable 0618
            var config = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618
            var exception = Assert.Throws<NotSupportedException>(() => 
                config.ContentEncryptionAlgorithm = ContentEncryptionAlgorithm.AesGcmWithCommitment);
            
            Assert.Contains("not supported for AmazonS3CryptoConfigurationV2", exception.Message);
            Assert.Contains("Please use AmazonS3EncryptionClientV4 instead", exception.Message);
            
            //= ../specification/s3-encryption/client.md#key-commitment
            //= type=test
            //# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
            var exceptionOnNewConfig = Assert.Throws<NotSupportedException>(() => 
                new AmazonS3CryptoConfigurationV2(SecurityProfile.V2, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment));
            Assert.Contains("The content encryption algorithm is not supported for AmazonS3CryptoConfigurationV2", exceptionOnNewConfig.Message);
        }

        [Theory]
        [InlineData(CommitmentPolicy.RequireEncryptAllowDecrypt)]
        [InlineData(CommitmentPolicy.RequireEncryptRequireDecrypt)]
        public void CommitmentPolicy_SetUnsupportedPolicy_ThrowsNotSupportedException(CommitmentPolicy policy)
        {
#pragma warning disable 0618
            var config = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618
            var exception = Assert.Throws<NotSupportedException>(() => 
                config.CommitmentPolicy = policy);
            
            Assert.Contains("not supported for AmazonS3CryptoConfigurationV2", exception.Message);
            Assert.Contains("Please use AmazonS3EncryptionClientV4 instead", exception.Message);
            
            //= ../specification/s3-encryption/client.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
            var exceptionOnNewConfig = Assert.Throws<NotSupportedException>(() => 
                new AmazonS3CryptoConfigurationV2(SecurityProfile.V2, policy, ContentEncryptionAlgorithm.AesGcm));
            Assert.Contains("not supported for AmazonS3CryptoConfigurationV2", exceptionOnNewConfig.Message);
            Assert.Contains("Please use AmazonS3EncryptionClientV4 instead", exceptionOnNewConfig.Message);
        }

        [Fact]
        public void CommitmentPolicy_SetForbidEncryptAllowDecrypt_SetsValueSuccessfully()
        {
#pragma warning disable 0618
            var config = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618   
            config.CommitmentPolicy = CommitmentPolicy.ForbidEncryptAllowDecrypt;
            
            Assert.Equal(CommitmentPolicy.ForbidEncryptAllowDecrypt, config.CommitmentPolicy);
        }
        
        [Fact]
        public void AmazonS3CryptoConfiguration_DefaultStorageMode_IsObjectMetadata()
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //= type=test
            //# By default, the S3EC MUST store content metadata in the S3 Object Metadata.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=test
            //# Instruction File writes MUST NOT be enabled by default.
            
            //= ../specification/s3-encryption/client.md#instruction-file-configuration
            //= type=test
            //# In this case, the Instruction File Configuration SHOULD be optional, such that its default configuration is used when none is provided.
    
            var configurationV4 = new AmazonS3CryptoConfigurationV4();
#pragma warning disable 0618
            var configurationV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618
            Assert.Equal(CryptoStorageMode.ObjectMetadata, configurationV4.StorageMode);
            Assert.Equal(CryptoStorageMode.ObjectMetadata, configurationV2.StorageMode);
        }
    }
}
