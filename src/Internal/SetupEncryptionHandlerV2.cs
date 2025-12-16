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

using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Runtime;
using Amazon.S3.Model;
using System;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV2.
    /// </summary>
    public class SetupEncryptionHandlerV2 : SetupEncryptionHandler
    {
        /// <summary>
        /// Algorithm suite used for encryption by S3 encryption client V2
        /// </summary>
        private readonly AlgorithmSuite _aes256GcmIv12Tag16NoKdf = AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf;
        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterialsV2 EncryptionMaterials => (EncryptionMaterialsV2)EncryptionClient.EncryptionMaterials;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV2.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandlerV2(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

        /// <inheritdoc/>
        public override void InvokeSync(IExecutionContext executionContext)
        {
            try
            {
                base.InvokeSync(executionContext);
            }
            catch (Exception)
            {
                HandleException(executionContext);
                throw;
            }
        }

#if AWS_ASYNC_API
        /// <inheritdoc/>
        public override async System.Threading.Tasks.Task<T> InvokeAsync<T>(IExecutionContext executionContext)
        {
            try
            {
                return await base.InvokeAsync<T>(executionContext);
            }
            catch (Exception)
            {
                HandleException(executionContext);
                throw;
            }
        }
#endif

        /// <summary>
        /// If the crypto stream that is reused for each part has its disposed disabled then the SDK 
        /// did not close the stream after the exception occurred. This method is called after a exception
        /// has ocurred and force the crypto stream to be closed.
        /// </summary>
        /// <param name="executionContext"></param>
        private void HandleException(IExecutionContext executionContext)
        {
            var request = executionContext.RequestContext.OriginalRequest;
            var uploadPartRequest = request as UploadPartRequest;
            if (uploadPartRequest != null)
            {
                var contextForEncryption = this.EncryptionClient.CurrentMultiPartUploadKeys[uploadPartRequest.UploadId];
                if (contextForEncryption == null)
                    return;

                var aesGcmEncryptStream = contextForEncryption.CryptoStream as AesGcmEncryptStream;
                if (aesGcmEncryptStream == null)
                    return;

                if (aesGcmEncryptStream.DisableDispose)
                {
                    aesGcmEncryptStream.DisableDispose = false;
                    aesGcmEncryptStream.Dispose();
                }
            }
        }

        /// <inheritdoc/>
        protected override EncryptionInstructions GenerateInstructions(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForKMSMaterialsV2(EncryptionClient.KMSClient, EncryptionMaterials, _aes256GcmIv12Tag16NoKdf);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials, _aes256GcmIv12Tag16NoKdf);
            }

            return instructions;
        }

        /// <inheritdoc/>
        protected override PutObjectRequest GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingAesGcm(putObjectRequest.InputStream, instructions, putObjectRequest.CalculateContentMD5Header);

            // Create request for uploading instruction file 
            PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV2(putObjectRequest, instructions);
            return instructionFileRequest;
        }

#if AWS_ASYNC_API
        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsAsync(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = await EncryptionUtils.GenerateInstructionsForKMSMaterialsV2Async(EncryptionClient.KMSClient, EncryptionMaterials, _aes256GcmIv12Tag16NoKdf)
                    .ConfigureAwait(false);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials, _aes256GcmIv12Tag16NoKdf);
            }

            return instructions;
        }
#endif

        /// <inheritdoc/>
        protected override void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingAesGcm(putObjectRequest.InputStream, instructions, putObjectRequest.CalculateContentMD5Header);

            // Update the metadata
            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(putObjectRequest, instructions);
        }

        /// <inheritdoc/>
        protected override void GenerateInitiateMultiPartUploadRequest(EncryptionInstructions instructions, InitiateMultipartUploadRequest initiateMultiPartUploadRequest, bool useKmsKeyWrapping)
        {
            ValidateConfigAndMaterials();
            if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
            {
                EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(initiateMultiPartUploadRequest, instructions);
            }

            var context = new UploadPartEncryptionContext
            {
                StorageMode = EncryptionClient.S3CryptoConfig.StorageMode,
                EncryptedEnvelopeKey = instructions.EncryptedEnvelopeKey,
                EnvelopeKey = instructions.EnvelopeKey,
                FirstIV = instructions.InitializationVector,
                NextIV = instructions.InitializationVector,
                PartNumber = 0,
                AlgorithmSuite = instructions.AlgorithmSuite,
                WrapAlgorithm = instructions.WrapAlgorithm,
            };
            EncryptionClient.AllMultiPartUploadRequestContexts[initiateMultiPartUploadRequest] = context;
        }

        /// <inheritdoc/>
        protected override void GenerateEncryptedUploadPartRequest(UploadPartRequest request)
        {
            string uploadID = request.UploadId;

            var contextForEncryption = this.EncryptionClient.CurrentMultiPartUploadKeys[uploadID];
            var envelopeKey = contextForEncryption.EnvelopeKey;
            var IV = contextForEncryption.NextIV;

            var instructions = new EncryptionInstructions(EncryptionMaterials.MaterialsDescription, envelopeKey, IV);

            if (request.IsLastPart == false)
            {
                if (contextForEncryption.IsFinalPart)
                    throw new AmazonClientException("Last part has already been processed, cannot upload this as the last part");

                if (request.PartNumber < contextForEncryption.PartNumber)
                    throw new AmazonClientException($"Upload Parts must be in correct sequence. Request part number {request.PartNumber} must be >= to {contextForEncryption.PartNumber}");

                UpdateRequestInputStream(request, contextForEncryption, instructions);
                contextForEncryption.PartNumber = request.PartNumber;
            }
            else
            {
                UpdateRequestInputStream(request, contextForEncryption, instructions);
                contextForEncryption.IsFinalPart = true;
            }
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(Constants.S3CryptoStreamRequestState, request.InputStream);

        }

        private static void UpdateRequestInputStream(UploadPartRequest request, UploadPartEncryptionContext contextForEncryption, EncryptionInstructions instructions)
        {
            if (contextForEncryption.CryptoStream == null)
            {
                request.InputStream = EncryptionUtils.EncryptUploadPartRequestUsingInstructionsV2(request.InputStream, instructions);
            }
            else
            {
                request.InputStream = contextForEncryption.CryptoStream;
            }

            // Clear the buffer filled for retry request
            var aesGcmEncryptCachingStream = request.InputStream as AesGcmEncryptCachingStream;
            if (aesGcmEncryptCachingStream != null)
            {                
                aesGcmEncryptCachingStream.ClearReadBufferToPosition();
            }

            var aesGcmEncryptStream = request.InputStream as AesGcmEncryptStream;
            if (aesGcmEncryptStream != null)
            {
                // The stream is reused across multi part uploads to maintain the encryption state.
                // The SDK will attempt to close the stream after the part is upload but setting
                // DisableDispose to true for anything besides the last part will make the 
                // disable a noop.
                aesGcmEncryptStream.DisableDispose = !request.IsLastPart;
            }
        }
    }
}
