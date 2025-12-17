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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.S3;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Base class for AmazonS3CryptoConfiguration configs
    /// Encapsulates common properties and methods of the AmazonS3CryptoConfiguration configurations
    /// </summary>
    public abstract class AmazonS3CryptoConfigurationBase: AmazonS3Config
    {
        //= ../specification/s3-encryption/client.md#instruction-file-configuration
        //# The S3EC MAY support the option to provide Instruction File Configuration during its initialization.
        
        //= ../specification/s3-encryption/client.md#instruction-file-configuration
        //# If the S3EC in a given language supports Instruction Files, then it MUST accept Instruction File Configuration during its initialization.
        
        /// <summary>
        /// Gets and sets the StorageMode property. This determines if the crypto metadata is stored as metadata on the object or as a separate object in S3.
        /// The default is ObjectMetadata.
        /// </summary>
        public CryptoStorageMode StorageMode { get; set; }
        
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=implication
        //# Instruction File writes MUST be optionally configured during client creation or on each PutObject request.

        /// <summary>
        /// Default Constructor.
        /// </summary>
        public AmazonS3CryptoConfigurationBase()
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //# By default, the S3EC MUST store content metadata in the S3 Object Metadata.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# Instruction File writes MUST NOT be enabled by default.
            
            //= ../specification/s3-encryption/client.md#instruction-file-configuration
            //# In this case, the Instruction File Configuration SHOULD be optional, such that its default configuration is used when none is provided.
            StorageMode = CryptoStorageMode.ObjectMetadata;
        }
        /// <summary>
        /// Configuration for the AWS Key Management Service client that will be used internally when encrypting S3 objects with KMS keys.
        /// </summary>
        /// <remarks>
        /// If not specified here, the internal KMS client will inherit the region, timeout, and proxy configuration from the S3 configuration
        /// </remarks>
        public AmazonKeyManagementServiceConfig KmsConfig { get; set; }

    }
}