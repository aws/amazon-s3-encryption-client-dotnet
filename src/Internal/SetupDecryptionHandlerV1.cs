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

using System.Collections.Generic;
using System.IO;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;
using Amazon.Extensions.S3.Encryption.Util;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom the pipeline handler to decrypt objects for AmazonS3EncryptionClient.
    /// </summary>
    public class SetupDecryptionHandlerV1 : SetupDecryptionHandler
    {
        private const string KMSKeyIDMetadataMessage = "Unable to determine the KMS key ID from the object metadata.";

        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterials EncryptionMaterials => (EncryptionMaterials)EncryptionClient.EncryptionMaterials;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV1.
        /// </summary>
        /// <param name="encryptionClient">Encryption client used to put and get objects</param>
        public SetupDecryptionHandlerV1(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

        private static string GetKmsKeyIdFromMetadata(MetadataCollection metadata)
        {
            var materialDescriptionJsonString = metadata[EncryptionUtils.XAmzMatDesc];
            if (materialDescriptionJsonString == null)
            {
                throw new InvalidDataException( $"{KMSKeyIDMetadataMessage} The key '{EncryptionUtils.XAmzMatDesc}' is missing.");
            }
            else
            {
                Dictionary<string,string> materialDescriptionJsonData;
                try
                {
                    materialDescriptionJsonData = JsonUtils.ToDictionary(materialDescriptionJsonString);
                }
                catch (InvalidDataException e)
                {
                    throw new InvalidDataException($"{KMSKeyIDMetadataMessage} The key '{EncryptionUtils.XAmzMatDesc}' does not contain valid JSON.", e);
                }

                if (!materialDescriptionJsonData.TryGetValue(EncryptionUtils.KMSCmkIDKey, out var kmsKeyIDJsonData))
                {
                    throw new InvalidDataException($"{KMSKeyIDMetadataMessage} The key '{kmsKeyIDJsonData}' is missing from the material description.");
                }

                return kmsKeyIDJsonData.ToString();
            }
        }

#if NETFRAMEWORK
        /// <inheritdoc/>
        protected override void CompleteMultipartUpload(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = this.EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];
            
            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFile(context, EncryptionMaterials);
                var instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(completeMultiPartUploadRequest, instructions);
                this.EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
            }

            //Clear Context data since encryption is completed
            this.EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }

        /// <inheritdoc/>
        protected override byte[] DecryptedEnvelopeKeyKms(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext)
        {
            var request = new DecryptRequest()
            {
                CiphertextBlob = new MemoryStream(encryptedKMSEnvelopeKey),
                EncryptionContext = encryptionContext
            };
            var response = EncryptionClient.KMSClient.Decrypt(request);
            return response.Plaintext.ToArray();
        }
#endif

        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task CompleteMultipartUploadAsync(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = this.EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];
            
            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFile(context, EncryptionMaterials);
                var instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(completeMultiPartUploadRequest, instructions);
                await EncryptionClient.S3ClientForInstructionFile.PutObjectAsync(instructionFileRequest)
                    .ConfigureAwait(false);
            }

            //Clear Context data since encryption is completed
            this.EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(completeMultiPartUploadRequest.UploadId, out _);
        }


        /// <inheritdoc />
        protected override async System.Threading.Tasks.Task<byte[]> DecryptedEnvelopeKeyKmsAsync(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext)
        {
            var request = new DecryptRequest()
            {
                CiphertextBlob = new MemoryStream(encryptedKMSEnvelopeKey),
                EncryptionContext = encryptionContext
            };
            var response = await EncryptionClient.KMSClient.DecryptAsync(request).ConfigureAwait(false);
            return response.Plaintext.ToArray();
        }

        /// <inheritdoc />
        protected override void ThrowIfLegacyReadIsDisabled()
        {
            // V1n doesn't need to throw any exception
        }

        /// <summary>
        /// Update multipart upload encryption context for the given UploadPartRequest
        /// </summary>
        /// <param name="uploadPartRequest">UploadPartRequest whose context needs to be updated</param>
        /// <exception cref="AmazonS3Exception">Exception throw if fails to update the encryption context</exception>
        protected override void UpdateMultipartUploadEncryptionContext(UploadPartRequest uploadPartRequest)
        {
            string uploadID = uploadPartRequest.UploadId;
            UploadPartEncryptionContext encryptedUploadedContext = null;

            if (!this.EncryptionClient.CurrentMultiPartUploadKeys.TryGetValue(uploadID, out encryptedUploadedContext))
                throw new AmazonS3Exception("Encryption context for multipart upload not found");

            if (!uploadPartRequest.IsLastPart)
            {
                object stream = null;

                if (!((Amazon.Runtime.Internal.IAmazonWebServiceRequest) uploadPartRequest).RequestState.TryGetValue(Constants.S3CryptoStreamRequestState, out stream))
                    throw new AmazonS3Exception("Cannot retrieve S3 crypto stream from request state, hence cannot get Initialization vector for next uploadPart ");

                var encryptionStream = stream as AESEncryptionUploadPartStream;
                if (encryptionStream != null)
                {
                    encryptedUploadedContext.NextIV = encryptionStream.InitializationVector;
                }
            }
        }
    }
}
