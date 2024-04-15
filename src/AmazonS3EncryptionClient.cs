/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 * 
 *  http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.Extensions.S3.Encryption.Internal;
using System.Reflection;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// This class extends the AmazonS3Client and provides client side encryption when reading or writing S3 objects.
    /// </summary>
    [Obsolete("This feature is in maintenance mode, no new updates will be released. Please see https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html for more information.")]
    public partial class AmazonS3EncryptionClient : AmazonS3EncryptionClientBase
    {
        private static readonly string _assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? string.Empty;
        private static readonly string _userAgentString = $"lib/amazon-extensions-s3-encryption#{_assemblyVersion} ft/s3-crypto-v1";

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(EncryptionMaterials materials) : base(materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(RegionEndpoint region, EncryptionMaterials materials) 
            : base(region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(AmazonS3CryptoConfiguration config, EncryptionMaterials materials) 
            : base(config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(AWSCredentials credentials, EncryptionMaterials materials) 
            : base(credentials, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(AWSCredentials credentials, RegionEndpoint region, EncryptionMaterials materials) 
            : base(credentials, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(AWSCredentials credentials, AmazonS3CryptoConfiguration config, EncryptionMaterials materials) 
            : base(credentials, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, RegionEndpoint region, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, AmazonS3CryptoConfiguration config, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, RegionEndpoint region, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfiguration();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, AmazonS3CryptoConfiguration config, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, config, materials)
        {
        }

        ///<inheritdoc/>
        protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
        {
            base.CustomizeRuntimePipeline(pipeline);

            pipeline.AddHandlerBefore<Amazon.Runtime.Internal.Marshaller>(new SetupEncryptionHandlerV1(this));
            pipeline.AddHandlerAfter<Amazon.Runtime.Internal.Marshaller>(new UserAgentHandler(_userAgentString));
            pipeline.AddHandlerBefore<Amazon.S3.Internal.AmazonS3ResponseHandler>(new SetupDecryptionHandlerV1(this));
        }
    }
}
