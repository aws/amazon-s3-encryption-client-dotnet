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
using Amazon.Runtime.Internal.Util;

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
        private CommitmentPolicy _commitmentPolicy;
        private ContentEncryptionAlgorithm _contentEncryptionAlgorithm;
        
        //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
        //= type=implication
        //# The S3EC MUST support the option to enable or disable legacy unauthenticated modes (content encryption algorithms).
        
        /// <summary>
        /// Determines enabled key wrap and content encryption schemas
        /// </summary>
        public SecurityProfile SecurityProfile
        {
            get => _securityProfile;
            set
            {
                if (value != SecurityProfile.V2 && value != SecurityProfile.V2AndLegacy)
                    throw new NotSupportedException($"The security profile {nameof(value)} is not supported for {nameof(AmazonS3CryptoConfigurationV2)}. ");
                
                _securityProfile = value;

                if (_securityProfile == SecurityProfile.V2AndLegacy)
                {
                    _logger.InfoFormat($"The {nameof(AmazonS3CryptoConfigurationV2)} is configured to read encrypted data with legacy encryption modes." +
                                      " If you don't have objects encrypted with these legacy modes, you should disable support for them to enhance security." +
                                     $" See {EncryptionUtils.SDKEncryptionDocsUrl}");
                }
            }
        }
        
        /// <summary>
        /// Determines the key commitment policy for encrypt/decrypt operations.
        /// </summary>
        public ContentEncryptionAlgorithm ContentEncryptionAlgorithm
        {
            get => _contentEncryptionAlgorithm;
            set
            {
                //= ../specification/s3-encryption/client.md#key-commitment
                //# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
                // V2 only supports AES GCM content encryption
                if (value == ContentEncryptionAlgorithm.AesGcmWithCommitment)
                {
                    throw new NotSupportedException($"The content encryption algorithm is not supported for {nameof(AmazonS3CryptoConfigurationV2)}. " +
                                                    "Please use AmazonS3EncryptionClientV4 instead.");
                }
                
                _contentEncryptionAlgorithm = value;
            }
        }
        
        /// <summary>
        /// Determines the key commitment policy for encrypt/decrypt operations.
        /// </summary>
        public CommitmentPolicy CommitmentPolicy
        {
            get => _commitmentPolicy;
            set
            {
                //= ../specification/s3-encryption/client.md#key-commitment
                //# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
                // V2 only supports AES GCM content encryption
                if (value == CommitmentPolicy.RequireEncryptAllowDecrypt || value == CommitmentPolicy.RequireEncryptRequireDecrypt)
                {
                    throw new NotSupportedException($"The commitment policy is not supported for {nameof(AmazonS3CryptoConfigurationV2)}. " +
                                                    "Please use AmazonS3EncryptionClientV4 instead.");
                }
                
                if (value == CommitmentPolicy.ForbidEncryptAllowDecrypt)
                {
                    _logger.InfoFormat("The CommitmentPolicy is set to ForbidEncryptAllowDecrypt. " +
                                       "This policy allows decryption of objects encrypted without key commitment but " +
                                       "forbids encryption with key commitment.");
                }
                
                _commitmentPolicy = value;
            }
        }
        
        //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
        //= type=exception
        //# The option to enable legacy unauthenticated modes MUST be set to false by default.

        /// <summary>
        /// Default Constructor.
        /// </summary>
        [Obsolete("This constructor is now obsolete. Please use AmazonS3CryptoConfigurationV2(SecurityProfile, CommitmentPolicy, ContentEncryptionAlgorithm)")]
        public AmazonS3CryptoConfigurationV2(SecurityProfile securityProfile)
        {
            _logger = Logger.GetLogger(GetType());
            SecurityProfile = securityProfile;
            // content encryption is AES GCM and CommitmentPolicy is ForbidEncryptAllowDecrypt to maintain backward compatibility.
            ContentEncryptionAlgorithm = ContentEncryptionAlgorithm.AesGcm;
            CommitmentPolicy = CommitmentPolicy.ForbidEncryptAllowDecrypt;
        }
        
        //= ../specification/s3-encryption/client.md#encryption-algorithm
        //= type=exception
        //= reason=There is no way to configure encryption algorithm that is legacy in S3EC NET as it's not supported. AES GCM with/without key commitment is not legacy.
        //# The S3EC MUST validate that the configured encryption algorithm is not legacy.
        
        //= ../specification/s3-encryption/client.md#encryption-algorithm
        //= type=exception
        //= reason=There is no way to configure encryption algorithm that is legacy in S3EC NET as it's not supported. AES GCM with/without key commitment is not legacy.
        //# If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
        
        //= ../specification/s3-encryption/client.md#encryption-algorithm
        //# The S3EC MUST support configuration of the encryption algorithm (or algorithm suite) during its initialization.
        
        //= ../specification/s3-encryption/client.md#key-commitment
        //# The S3EC MUST support configuration of the [Key Commitment policy](./key-commitment.md) during its initialization.
        
        /// <summary>
        /// Constructor with securityProfile, commitmentPolicy and contentEncryptionAlgorithm.
        /// </summary>
        public AmazonS3CryptoConfigurationV2(SecurityProfile securityProfile, CommitmentPolicy commitmentPolicy, ContentEncryptionAlgorithm contentEncryptionAlgorithm)
        {
            _logger = Logger.GetLogger(GetType());
            SecurityProfile = securityProfile;
            CommitmentPolicy = commitmentPolicy;
            ContentEncryptionAlgorithm = contentEncryptionAlgorithm;
        }
    }
}