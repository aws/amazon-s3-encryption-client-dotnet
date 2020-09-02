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
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom the pipeline handler to decrypt objects for AmazonS3EncryptionClientV2.
    /// </summary>
    public class SetupDecryptionHandlerV2 : SetupDecryptionHandler
    {
        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterialsV2 EncryptionMaterials => (EncryptionMaterialsV2)EncryptionClient.EncryptionMaterials;

        /// <summary>
        /// Crypto configuration of the encryption client
        /// </summary>
        internal AmazonS3CryptoConfigurationV2 CryptoConfiguration => EncryptionClient.S3CryptoConfig as AmazonS3CryptoConfigurationV2;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV2.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupDecryptionHandlerV2(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

#if BCL
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
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV2(context, EncryptionMaterials);
                var instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV2(completeMultiPartUploadRequest, instructions);
                EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }
#endif

#if AWS_ASYNC_API

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
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV2(context, EncryptionMaterials);
                PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV2(completeMultiPartUploadRequest, instructions);
                await EncryptionClient.S3ClientForInstructionFile.PutObjectAsync(instructionFileRequest).ConfigureAwait(false);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }
#endif

        /// <inheritdoc />
        protected override void ThrowIfLegacyReadIsDisabled()
        {
            if (CryptoConfiguration.SecurityProfile == SecurityProfile.V2)
            {
                throw new AmazonCryptoException($"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V2)}." +
                                                $" Retry with {nameof(SecurityProfile.V2AndLegacy)} enabled or reencrypt the object.");
            }
        }

        /// <inheritdoc/>
        protected override void UpdateMultipartUploadEncryptionContext(UploadPartRequest uploadPartRequest)
        {
            string uploadID = uploadPartRequest.UploadId;
            UploadPartEncryptionContext encryptedUploadedContext = null;

            if (!EncryptionClient.CurrentMultiPartUploadKeys.TryGetValue(uploadID, out encryptedUploadedContext))
                throw new AmazonS3Exception("Encryption context for multipart upload not found");

            if (!uploadPartRequest.IsLastPart)
            {
                object stream = null;

                if (!((IAmazonWebServiceRequest) uploadPartRequest).RequestState.TryGetValue(AmazonS3EncryptionClient.S3CryptoStream, out stream))
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
