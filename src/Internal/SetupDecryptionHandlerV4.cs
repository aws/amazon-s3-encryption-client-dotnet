﻿/*
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
using System.IO;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom the pipeline handler to decrypt objects for AmazonS3EncryptionClientV4.
    /// </summary>
    public class SetupDecryptionHandlerV4 : SetupDecryptionHandler
    {
        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterialsV4 EncryptionMaterials => (EncryptionMaterialsV4)EncryptionClient.EncryptionMaterials;

        /// <summary>
        /// Crypto configuration of the encryption client
        /// </summary>
        internal AmazonS3CryptoConfigurationV4 CryptoConfiguration => EncryptionClient.S3CryptoConfig as AmazonS3CryptoConfigurationV4;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV4.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupDecryptionHandlerV4(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

#if NETFRAMEWORK
        /// <inheritdoc/>
        protected override byte[] DecryptedEnvelopeKeyKms(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext)
        {
            var request = new DecryptRequest()
            {
                KeyId = EncryptionClient.EncryptionMaterials.KMSKeyID,
                CiphertextBlob = new MemoryStream(encryptedKMSEnvelopeKey),
                EncryptionContext = encryptionContext
            };
            var response = EncryptionClient.KMSClient.Decrypt(request);
            return response.Plaintext.ToArray();
        }

        /// <inheritdoc/>
        protected override void CompleteMultipartUpload(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];
            
            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV3(context, EncryptionMaterials, context.AlgorithmSuite);
                var instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV3(completeMultiPartUploadRequest, instructions);
                EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }
#endif

        /// <inheritdoc />
        protected override async System.Threading.Tasks.Task<byte[]> DecryptedEnvelopeKeyKmsAsync(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext)
        {
            var request = new DecryptRequest()
            {
                KeyId = EncryptionClient.EncryptionMaterials.KMSKeyID,
                CiphertextBlob = new MemoryStream(encryptedKMSEnvelopeKey),
                EncryptionContext = encryptionContext
            };
            var response = await EncryptionClient.KMSClient.DecryptAsync(request).ConfigureAwait(false);
            return response.Plaintext.ToArray();
        }

        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task CompleteMultipartUploadAsync(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];
            
            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV3(context, EncryptionMaterials, context.AlgorithmSuite);
                PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV3(completeMultiPartUploadRequest, instructions);
                await EncryptionClient.S3ClientForInstructionFile.PutObjectAsync(instructionFileRequest).ConfigureAwait(false);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }

        /// <inheritdoc />
        protected override void ThrowIfLegacyReadIsDisabled()
        {
            //= ../specification/s3-encryption/decryption.md#legacy-decryption
            //# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
            if (CryptoConfiguration.SecurityProfile == SecurityProfile.V4)
            {
                //= ../specification/s3-encryption/decryption.md#legacy-decryption
                //# If the S3EC is not configured to enable legacy unauthenticated content decryption, the client MUST throw an exception when attempting to decrypt an object encrypted with a legacy unauthenticated algorithm suite.
                throw new AmazonCryptoException($"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V4)}." +
                                                $" Retry with {nameof(SecurityProfile.V4AndLegacy)} enabled or reencrypt the object.");
            }
        }
        
        /// <inheritdoc />
        protected override void ThrowIfDecryptNonCommitingDisabled(MetadataCollection objectMetaData)
        {
            if (ContentMetaDataV3Utils.IsV3Object(objectMetaData))
            {
                return;
            }
            if (CommitmentPolicy.RequireEncryptRequireDecrypt == CryptoConfiguration.CommitmentPolicy)
            {
                throw new ArgumentException("The requested object is encrypted with non key committing algorithm" +
                                            $" but commitment policy is set to {nameof(CommitmentPolicy.RequireEncryptRequireDecrypt)}." +
                                            " This commitment policy does not allow decryption of object encrypted with non key committing algorithm." +
                                            $" Retry with {nameof(CommitmentPolicy.RequireEncryptAllowDecrypt)} to encrypt with key committing algorithm" +
                                            " and allow decryption for object encrypted with non key committing algorithm.");
            }
        }

        /// <inheritdoc/>
        protected override void UpdateMultipartUploadEncryptionContext(UploadPartRequest uploadPartRequest)
        {
            string uploadID = uploadPartRequest.UploadId;
            UploadPartEncryptionContext encryptedUploadedContext = null;

            if (!EncryptionClient.CurrentMultiPartUploadKeys.TryGetValue(uploadID, out encryptedUploadedContext))
                throw new AmazonS3Exception("Context of encryption for multipart upload not found");

            if (!uploadPartRequest.IsLastPart)
            {
                object stream = null;

                if (!((IAmazonWebServiceRequest) uploadPartRequest).RequestState.TryGetValue(Constants.S3CryptoStreamRequestState, out stream))
                    throw new AmazonS3Exception("Cannot retrieve S3 crypto stream from request state, hence cannot get Initialization vector for next uploadPart ");
                
                var encryptionStream = stream as AESEncryptionUploadPartStream;
                if (encryptionStream != null)
                {
                    encryptedUploadedContext.NextIV = encryptionStream.InitializationVector;
                }
                
                var aesGcmEncryptStream = stream as AesGcmEncryptStream;
                if (aesGcmEncryptStream != null)
                {
                    encryptedUploadedContext.CryptoStream = aesGcmEncryptStream;
                }
            }
        }
    }
}
