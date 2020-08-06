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

 namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV2.
    /// </summary>
    public class SetupEncryptionHandlerV2 : SetupEncryptionHandler
    {
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
        protected override EncryptionInstructions GenerateInstructions(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForKMSMaterialsV2(EncryptionClient.KMSClient, EncryptionMaterials);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials);
            }

            return instructions;
        }

        /// <inheritdoc/>
        protected override PutObjectRequest GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstructionV2(putObjectRequest.InputStream, instructions);

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
                instructions = await EncryptionUtils.GenerateInstructionsForKMSMaterialsV2Async(EncryptionClient.KMSClient, EncryptionMaterials)
                    .ConfigureAwait(false);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials);
            }

            return instructions;
        }
#endif

        /// <inheritdoc/>
        protected override void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstructionV2(putObjectRequest.InputStream, instructions);

            // Update the metadata
            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(putObjectRequest, instructions, EncryptionClient);
        }

        /// <inheritdoc/>
        protected override void GenerateInitiateMultiPartUploadRequest(EncryptionInstructions instructions, InitiateMultipartUploadRequest initiateMultiPartUploadRequest, bool useKmsKeyWrapping)
        {
            ValidateConfigAndMaterials();
            if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
            {
                EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(initiateMultiPartUploadRequest, instructions, EncryptionClient);
            }

            var context = new UploadPartEncryptionContext
            {
                StorageMode = EncryptionClient.S3CryptoConfig.StorageMode,
                EncryptedEnvelopeKey = instructions.EncryptedEnvelopeKey,
                EnvelopeKey = instructions.EnvelopeKey,
                FirstIV = instructions.InitializationVector,
                NextIV = instructions.InitializationVector,
                PartNumber = 0,
                CekAlgorithm = instructions.CekAlgorithm,
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
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(AmazonS3EncryptionClient.S3CryptoStream, request.InputStream);

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
        }
    }
}
