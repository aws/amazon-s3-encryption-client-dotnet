/*
 * Copyright 2010-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// This class extends the AmazonS3Client and provides client side encryption when reading or writing S3 objects.
    /// </summary>
    [Obsolete("AmazonS3EncryptionClient is obsolete. Use AmazonS3EncryptionClientV2 which supports AES GCM mode for content encryption/decryption " +
              "and backward decryption compatible with AmazonS3EncryptionClient")]
    public partial class AmazonS3EncryptionClient : AmazonS3EncryptionClientBase
    {

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(EncryptionMaterials materials) : base(materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(RegionEndpoint region, EncryptionMaterials materials) 
            : base(region, materials)
        {
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
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(AWSCredentials credentials, RegionEndpoint region, EncryptionMaterials materials) 
            : base(credentials, region, materials)
        {
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
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, RegionEndpoint region, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, region, materials)
        {
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
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClient(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, RegionEndpoint region, EncryptionMaterials materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, region, materials)
        {
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
            pipeline.AddHandlerAfter<Amazon.Runtime.Internal.Marshaller>(new UserAgentHandler());
            pipeline.AddHandlerBefore<Amazon.S3.Internal.AmazonS3ResponseHandler>(new SetupDecryptionHandlerV1(this));
        }
    }
}
