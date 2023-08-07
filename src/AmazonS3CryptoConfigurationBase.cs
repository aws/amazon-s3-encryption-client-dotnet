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
        /// <summary>
        /// Gets and sets the StorageMode property. This determines if the crypto metadata is stored as metadata on the object or as a separate object in S3.
        /// The default is ObjectMetadata.
        /// </summary>
        public CryptoStorageMode StorageMode { get; set; }

        /// <summary>
        /// Default Constructor.
        /// </summary>
        public AmazonS3CryptoConfigurationBase()
        {
            // By default, store encryption info in metadata
            StorageMode = CryptoStorageMode.ObjectMetadata;
        }

        public AmazonKeyManagementServiceConfig KmsConfig { get; set; }

    }
}