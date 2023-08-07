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
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using System;
using System.Collections.Generic;
using Amazon.Runtime;
using Amazon.S3.Model;
using Amazon.Runtime.Internal;
using Amazon.S3;
using Amazon.KeyManagementService;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// AmazonS3CryptoConfigurationV2 allows customers
    /// to set storage mode for encryption credentials
    /// for AmazonS3EncryptionClientV2
    /// </summary>
    public class AmazonS3CryptoConfigurationV2: AmazonS3CryptoConfigurationBase
    {
        private readonly ILogger _logger;

        private SecurityProfile _securityProfile;

        /// <summary>
        /// Determines enabled key wrap and content encryption schemas
        /// The default is V2.
        /// </summary>
        public SecurityProfile SecurityProfile
        {
            get => _securityProfile;
            set
            {
                _securityProfile = value;

                if (_securityProfile == SecurityProfile.V2AndLegacy)
                {
                    _logger.InfoFormat($"The {nameof(AmazonS3CryptoConfigurationV2)} is configured to read encrypted data with legacy encryption modes." +
                                      " If you don't have objects encrypted with these legacy modes, you should disable support for them to enhance security." +
                                     $" See {EncryptionUtils.SDKEncryptionDocsUrl}");
                }
            }
        }
        
        public AmazonKeyManagementServiceConfig KmsConfig { get; set; }

        /// <summary>
        /// Default Constructor.
        /// </summary>
        public AmazonS3CryptoConfigurationV2(SecurityProfile securityProfile)
        {
            _logger = Logger.GetLogger(GetType());
            SecurityProfile = securityProfile;
        }
    }
}