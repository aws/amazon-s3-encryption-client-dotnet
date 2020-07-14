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

using System.Linq;
using Amazon.Runtime;
using Amazon.S3.Model;

namespace Amazon.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV1.
    /// </summary>
    public class SetupEncryptionHandlerV1 : SetupEncryptionHandler
    {
        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV1.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandlerV1(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

        ///<inheritdoc/>
        protected override void PreInvoke(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
                instructions = EncryptionUtils.GenerateInstructionsForKMSMaterials(
                    EncryptionClient.KMSClient, EncryptionClient.EncryptionMaterials);

            PreInvokeSynchronous(executionContext, instructions);
        }

#if AWS_ASYNC_API
        ///<inheritdoc/>
        protected override async System.Threading.Tasks.Task PreInvokeAsync(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
                instructions = await EncryptionUtils.GenerateInstructionsForKMSMaterialsAsync(
                    EncryptionClient.KMSClient, EncryptionClient.EncryptionMaterials).ConfigureAwait(false);

            PreInvokeSynchronous(executionContext, instructions);
        }
#endif

        /// <summary>
        /// Updates the request where the metadata contains encryption information 
        /// and the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="putObjectRequest">
        /// The request whose contents are to be encrypted.
        /// </param>
        /// <param name="instructions"></param>
        protected void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstruction(putObjectRequest.InputStream, instructions);

            // Update the metadata
            EncryptionUtils.UpdateMetadataWithEncryptionInstructions(putObjectRequest, instructions, 
                this.EncryptionClient.EncryptionMaterials.KMSKeyID != null, EncryptionClient.CekAlgorithm);
        }

        /// <summary>
        /// Updates the request where the instruction file contains encryption information 
        /// and the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="putObjectRequest"></param>
        /// <param name="instructions"></param>
        protected void GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstruction(putObjectRequest.InputStream, instructions);

            // Create request for uploading instruction file 
            PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(putObjectRequest, instructions);

            this.EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
        }
        
        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the AsymmetricProvider or SymmetricProvider set.
        /// </summary>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        private EncryptionInstructions GenerateInstructionsForNonKmsMaterials()
        {
            return EncryptionUtils.GenerateInstructionsForNonKMSMaterials(EncryptionClient.EncryptionMaterials);
        }
        
        ///<inheritdoc/>
        internal override void PreInvokeSynchronous(IExecutionContext executionContext, EncryptionInstructions instructions) 
        {
            var request = executionContext.RequestContext.OriginalRequest;
            var putObjectRequest = request as PutObjectRequest;
            var initiateMultiPartUploadRequest = request as InitiateMultipartUploadRequest;
            var uploadPartRequest = request as UploadPartRequest;
            var useKMSKeyWrapping = this.EncryptionClient.EncryptionMaterials.KMSKeyID != null;

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = GenerateInstructionsForNonKmsMaterials();
            }

            if (putObjectRequest != null)
            {
                ValidateConfigAndMaterials();
                if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
                    GenerateEncryptedObjectRequestUsingMetadata(putObjectRequest, instructions);
                else
                    GenerateEncryptedObjectRequestUsingInstructionFile(putObjectRequest, instructions);
            }

            if (initiateMultiPartUploadRequest != null)
            {
                ValidateConfigAndMaterials();
                if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
                {
                    EncryptionUtils.UpdateMetadataWithEncryptionInstructions(initiateMultiPartUploadRequest, instructions, useKMSKeyWrapping, EncryptionClient.CekAlgorithm);
                }

                initiateMultiPartUploadRequest.StorageMode = EncryptionClient.S3CryptoConfig.StorageMode;
                initiateMultiPartUploadRequest.EncryptedEnvelopeKey = instructions.EncryptedEnvelopeKey;
                initiateMultiPartUploadRequest.EnvelopeKey = instructions.EnvelopeKey;
                initiateMultiPartUploadRequest.IV = instructions.InitializationVector;
            }

            if (uploadPartRequest != null)
            {
                GenerateEncryptedUploadPartRequest(uploadPartRequest);
            }
        }
        
        /// <summary>
        /// Updates the request where the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="request"></param>
        private void GenerateEncryptedUploadPartRequest(UploadPartRequest request)
        {
            string uploadID = request.UploadId;

            UploadPartEncryptionContext contextForEncryption = this.EncryptionClient.CurrentMultiPartUploadKeys[uploadID];
            byte[] envelopeKey = contextForEncryption.EnvelopeKey;
            byte[] IV = contextForEncryption.NextIV;

            EncryptionInstructions instructions = new EncryptionInstructions(EncryptionClient.EncryptionMaterials.MaterialsDescription, envelopeKey, IV);

            if (!request.IsLastPart)
            {
                if (contextForEncryption.IsFinalPart)
                    throw new AmazonClientException("Last part has already been processed, cannot upload this as the last part");

                if (request.PartNumber < contextForEncryption.PartNumber)
                    throw new AmazonClientException($"Upload Parts must be in correct sequence. Request part number {request.PartNumber} must be >= to {contextForEncryption.PartNumber}");

                request.InputStream = EncryptionUtils.EncryptUploadPartRequestUsingInstructions(request.InputStream, instructions);
                contextForEncryption.PartNumber = request.PartNumber;
            }
            else
            {
                request.InputStream = EncryptionUtils.EncryptRequestUsingInstruction(request.InputStream, instructions);
                contextForEncryption.IsFinalPart = true;
            }
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(AmazonS3EncryptionClient.S3CryptoStream, request.InputStream);
        }
    }
}
