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
    /// AmazonS3CryptoConfigurationV4 allows customers to configure
    /// key commitment policy, security profile, and storage mode for encryption credentials
    /// for AmazonS3EncryptionClientV4
    /// </summary>
    public class AmazonS3CryptoConfigurationV4 : AmazonS3CryptoConfigurationBase
    {
        private readonly ILogger _logger;
        private CommitmentPolicy _commitmentPolicy;
        private SecurityProfile _securityProfile;
        private ContentEncryptionAlgorithm _contentEncryptionAlgorithm;
        
        /// <summary>
        /// Determines enabled key wrap and content encryption schemas
        /// </summary>
        public SecurityProfile SecurityProfile
        {
            get => _securityProfile;
            private set
            {
                if (value != SecurityProfile.V4 && value != SecurityProfile.V4AndLegacy)
                {
                    throw new NotSupportedException($"The security profile {nameof(value)} is not supported for {nameof(AmazonS3CryptoConfigurationV4)}. ");
                }
                
                _securityProfile = value;

                if (_securityProfile == SecurityProfile.V4AndLegacy)
                {
                    _logger.InfoFormat($"The {nameof(AmazonS3CryptoConfigurationV4)} is configured to read encrypted data with non key commiting encryption modes.");
                }
            }
        }
        
        /// <summary>
        /// Determines the key commitment policy for encrypt/decrypt operations.
        /// </summary>
        public CommitmentPolicy CommitmentPolicy
        {
            get => _commitmentPolicy;
            private set
            {
                if (value == CommitmentPolicy.ForbidEncryptAllowDecrypt)
                {
                    _logger.InfoFormat("The CommitmentPolicy is set to ForbidEncryptAllowDecrypt. " +
                                      "This policy allows decryption of objects encrypted without key commitment but " +
                                      "forbids encryption with key commitment. Consider using RequireEncryptRequireDecrypt for better security.");
                }
                
                _commitmentPolicy = value;
            }
        }
        
        /// <summary>
        /// Determines the context encryption for encrypt/decrypt operations.
        /// </summary>
        public ContentEncryptionAlgorithm ContentEncryptionAlgorithm
        {
            get => _contentEncryptionAlgorithm;
            private set
            {
                if (value == ContentEncryptionAlgorithm.AesGcm)
                {
                    _logger.InfoFormat("The ContentEncryptionAlgorithm is set to AesGcm. " +
                                       "This enables encryption of objects without key commitment." +
                                       $" Consider using {nameof(ContentEncryptionAlgorithm.AesGcmWithCommitment)} for better security.");
                }
                _contentEncryptionAlgorithm = value;
            }
        }
        
        /// <summary>
        /// Constructor with commitment policy for S3EC V4 client
        /// This is the default constructor which uses V4 for SecurityProfile, RequireEncryptRequireDecrypt for CommitmentPolicy
        /// and AesGcmWithCommitment for ContentEncryptionAlgorithm.
        /// </summary>
        public AmazonS3CryptoConfigurationV4()
        {
            _logger = Logger.GetLogger(GetType());
            SecurityProfile = SecurityProfile.V4;
            CommitmentPolicy = CommitmentPolicy.RequireEncryptRequireDecrypt;
            //= ../specification/s3-encryption/encryption.md#content-encryption
            //# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
            // AmazonS3CryptoConfigurationV4 must be sent to client.
            ContentEncryptionAlgorithm = ContentEncryptionAlgorithm.AesGcmWithCommitment;
        }

        /// <summary>
        /// Constructor with commitment policy.
        /// </summary>
        /// <param name="securityProfile">The securityProfile policy to enforce</param>
        /// <param name="commitmentPolicy">The key commitment policy to enforce</param>
        /// <param name="contentEncryptionAlgorithm">The content Encryption Algorithm to enforce</param>
        public AmazonS3CryptoConfigurationV4(SecurityProfile securityProfile, CommitmentPolicy commitmentPolicy, ContentEncryptionAlgorithm contentEncryptionAlgorithm)
        {
            ValidateConfiguration(commitmentPolicy, contentEncryptionAlgorithm);
            
            _logger = Logger.GetLogger(GetType());
            SecurityProfile = securityProfile;
            CommitmentPolicy = commitmentPolicy;
            //= ../specification/s3-encryption/encryption.md#content-encryption
            //# The S3EC MUST use the encryption algorithm configured during [client](./client.md) initialization.
            // AmazonS3CryptoConfigurationV4 must be sent to client.
            ContentEncryptionAlgorithm = contentEncryptionAlgorithm;
        }
        
        /// <summary>
        /// Validates Configuration (securityProfile, commitmentPolicy, contentEncryptionAlgorithm)
        /// if contentEncryptionAlgorithm is AesGcm, commitmentPolicy has to be ForbidEncryptAllowDecrypt and securityProfile has to be V4AndLegacy
        /// if contentEncryptionAlgorithm is AesGcmWithCommitment, commitmentPolicy has to be RequireEncryptRequireDecrypt/RequireEncryptAllowDecrypt
        /// </summary>
        /// <param name="commitmentPolicy">The key commitment policy to enforce</param>
        /// <param name="contentEncryptionAlgorithm">The content Encryption Algorithm to enforce</param>
        private static void ValidateConfiguration(CommitmentPolicy commitmentPolicy, ContentEncryptionAlgorithm contentEncryptionAlgorithm)
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            if (contentEncryptionAlgorithm == ContentEncryptionAlgorithm.AesGcm)
            {
                if (commitmentPolicy != CommitmentPolicy.ForbidEncryptAllowDecrypt)
                    throw new ArgumentException($"ContentEncryptionAlgorithm {nameof(ContentEncryptionAlgorithm.AesGcm)} is not committing and" +
                                                $"the Commitment Policy {nameof(commitmentPolicy)} requires commitment on encrypt. Use a committing encryption algorithm, " +
                                                $"or set a Commitment Policy which forbids commitment on encrypt such as:   {nameof(CommitmentPolicy.ForbidEncryptAllowDecrypt)}.");
            }
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
            if (contentEncryptionAlgorithm == ContentEncryptionAlgorithm.AesGcmWithCommitment)
            {
                if (commitmentPolicy != CommitmentPolicy.RequireEncryptRequireDecrypt && commitmentPolicy != CommitmentPolicy.RequireEncryptAllowDecrypt)
                    throw new ArgumentException($"ContentEncryptionAlgorithm {nameof(ContentEncryptionAlgorithm.AesGcmWithCommitment)}" +
                                                $"is committing and the Commitment Policy {nameof(commitmentPolicy)} " +
                                                "forbids commitment on encrypt. Use a non-committing encryption algorithm, or set a Commitment Policy which requires commitment on encrypt " +
                                                $"such as: {nameof(CommitmentPolicy.RequireEncryptRequireDecrypt)} or {nameof(CommitmentPolicy.RequireEncryptRequireDecrypt)}.");
            }
        }
    }
}
