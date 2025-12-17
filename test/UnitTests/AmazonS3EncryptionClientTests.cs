using System;
using System.Collections.Generic;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.KeyManagementService;
using Amazon.Runtime;
using Amazon.S3;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AmazonS3EncryptionClientTests
    {
        private readonly EncryptionMaterials _materials = new EncryptionMaterials("dummy-key-id");

        [Fact]
        public void S3EncryptionClient_UsesCustomKmsConfigWhenProvided()
        {
            var customKmsConfig = new AmazonKeyManagementServiceConfig
            {
                RegionEndpoint = RegionEndpoint.APSoutheast1,
                Timeout = TimeSpan.FromSeconds(60)
            };
            
            var s3Config = new AmazonS3CryptoConfiguration
            {
                KmsConfig = customKmsConfig,
                RegionEndpoint = RegionEndpoint.USEast1
            };
#pragma warning disable 0618
            var client = new AmazonS3EncryptionClient(s3Config, _materials); 
#pragma warning restore 0618
            var kmsClient = client.KMSClient;
            
            Assert.Equal(RegionEndpoint.APSoutheast1, kmsClient.Config.RegionEndpoint);
            Assert.Equal(TimeSpan.FromSeconds(60), kmsClient.Config.Timeout);
        }

        [Fact]
        public void S3EncryptionClient_KmsInheritsFromS3ConfigWhenNoCustomKmsConfig()
        {
            var s3Config = new AmazonS3CryptoConfiguration
            {
                RegionEndpoint = RegionEndpoint.EUCentral1,
                Timeout = TimeSpan.FromSeconds(30)
            };
#pragma warning disable 0618
            var client = new AmazonS3EncryptionClient(s3Config, _materials); 
#pragma warning restore 0618
            var kmsClient = client.KMSClient;
            
            Assert.Equal(s3Config.RegionEndpoint, kmsClient.Config.RegionEndpoint);
            Assert.Equal(s3Config.Timeout, kmsClient.Config.Timeout);
        }

        [Fact]
        public void S3EncryptionClient_AllWrappedClientsInheritBaseConfiguration()
        {
            var credentials = new BasicAWSCredentials("key", "secret");
            var config = new AmazonS3CryptoConfiguration
            {
                RegionEndpoint = RegionEndpoint.USWest2,
                Timeout = TimeSpan.FromSeconds(45)
            };
#pragma warning disable 0618
            var client = new AmazonS3EncryptionClient(
                //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
                //= type=test
                //# For example, the S3EC MAY accept a credentials provider instance during its initialization.
                credentials,
                //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
                //= type=test
                //# The S3EC MAY support directly configuring the wrapped SDK clients through its initialization.
                config, 
                _materials);
#pragma warning restore 0618
            Assert.Equal(config.RegionEndpoint, client.Config.RegionEndpoint);
            
            //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
            //= type=test
            //# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped S3 clients.
            
            //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
            //= type=test
            //# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped SDK clients including the KMS client.
            Assert.Equal(config.RegionEndpoint, client.S3ClientForInstructionFile.Config.RegionEndpoint);
            Assert.Equal(config.RegionEndpoint, client.KMSClient.Config.RegionEndpoint);
            
            // Use reflection to get the actual credentials from the s3 and kms clients since ExplicitAWSCredentials is not exposed
            var s3ClientCredentials = typeof(AmazonS3Client).GetProperty("ExplicitAWSCredentials", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
                .GetValue(client.S3ClientForInstructionFile);
            Assert.Equal(credentials, s3ClientCredentials);

            var kmsClientCredentials = typeof(AmazonKeyManagementServiceClient).GetProperty("ExplicitAWSCredentials", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
                .GetValue(client.KMSClient);
            Assert.Equal(credentials, kmsClientCredentials);
        }
    }
}