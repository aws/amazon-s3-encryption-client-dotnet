using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AmazonS3CryptoConfigurationTest
    {
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
    
            var configurationV1 = new AmazonS3CryptoConfiguration();
#pragma warning disable 0618
            var configurationV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
#pragma warning restore 0618
            Assert.Equal(CryptoStorageMode.ObjectMetadata, configurationV1.StorageMode);
            Assert.Equal(CryptoStorageMode.ObjectMetadata, configurationV2.StorageMode);
        }
    }
}