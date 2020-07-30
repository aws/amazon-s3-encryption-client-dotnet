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
using Amazon.Extensions.S3.Encryption.Internal;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// This class extends the AmazonS3Client and implements IAmazonS3Encryption
    /// Provides client side encryption when reading or writing S3 objects.
    /// Supported content ciphers:
    ///	AES/GCM - Encryption and decryption (Encrypted block size can be bigger than the input block size)
    ///	AES/CBC - Decryption only
    /// </summary>
    public partial class AmazonS3EncryptionClientV2 : AmazonS3EncryptionClientBase
    {
        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(EncryptionMaterialsV2 materials) 
            : base(materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(RegionEndpoint region, EncryptionMaterialsV2 materials) 
            : base(region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AWSCredentials credentials, EncryptionMaterialsV2 materials) 
            : base(credentials, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AWSCredentials credentials, RegionEndpoint region, EncryptionMaterialsV2 materials) 
            : base(credentials, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AWSCredentials credentials, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(credentials, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, RegionEndpoint region, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, RegionEndpoint region, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, region, materials)
        {
            S3CryptoConfig = new AmazonS3CryptoConfigurationV2();
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, config, materials)
        {
        }
        
        ///<inheritdoc/>
        protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
        {
            base.CustomizeRuntimePipeline(pipeline);

            pipeline.AddHandlerBefore<Amazon.Runtime.Internal.Marshaller>(new SetupEncryptionHandlerV2(this));
            pipeline.AddHandlerAfter<Amazon.Runtime.Internal.Marshaller>(new UserAgentHandler("S3CryptoV2"));
            pipeline.AddHandlerBefore<Amazon.S3.Internal.AmazonS3ResponseHandler>(new SetupDecryptionHandlerV2(this));
        }
    }
}
