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
using Amazon.Runtime;
using Amazon.S3.Model;
using Amazon.S3.Util;
using ThirdParty.Json.LitJson;

namespace Amazon.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV2.
    /// </summary>
    public class SetupEncryptionHandlerV2 : SetupEncryptionHandler
    {
        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV2.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandlerV2(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

        ///<inheritdoc/>
        protected override void PreInvoke(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                EncryptionClient.EncryptionMaterials.MaterialsDescription[EncryptionUtils.XAmzEncryptionContextCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue;
                instructions = EncryptionUtils.GenerateInstructionsForKMSMaterials(EncryptionClient.KMSClient, EncryptionClient.EncryptionMaterials);
            }

            PreInvokeSynchronous(executionContext, instructions);
        }

        /// <summary>
        /// Updates the request where the instruction file contains encryption information 
        /// and the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="putObjectRequest"></param>
        /// <param name="instructions"></param>
        private void GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstructionV2(putObjectRequest.InputStream, instructions);

            // Set AES GCM specific data
            instructions.MaterialsDescription[EncryptionUtils.XAmzCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue;
            instructions.MaterialsDescription[EncryptionUtils.XAmzTagLen] = EncryptionUtils.DefaultTagLength.ToString();
            instructions.MaterialsDescription[EncryptionUtils.XAmzWrapAlg] = EncryptionUtils.XAmzWrapAlgRsaOaepSha1;

            // Create request for uploading instruction file 
            PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(putObjectRequest, instructions);

            EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
        }

#if AWS_ASYNC_API
        ///<inheritdoc/>
        protected override async System.Threading.Tasks.Task PreInvokeAsync(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                EncryptionClient.EncryptionMaterials.MaterialsDescription[EncryptionUtils.XAmzEncryptionContextCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue;

                instructions = await EncryptionUtils.GenerateInstructionsForKMSMaterialsV2Async(EncryptionClient.KMSClient, EncryptionClient.EncryptionMaterials)
                    .ConfigureAwait(false);
            }

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
        private void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstructionV2(putObjectRequest.InputStream, instructions);

            // Update the metadata
            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(putObjectRequest, instructions, EncryptionClient);
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
            return EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionClient.EncryptionMaterials);
        }

        ///<inheritdoc/>
        internal override void PreInvokeSynchronous(IExecutionContext executionContext, EncryptionInstructions instructions)
        {
            var request = executionContext.RequestContext.OriginalRequest;
            var putObjectRequest = request as PutObjectRequest;
            var initiateMultiPartUploadRequest = request as InitiateMultipartUploadRequest;
            var uploadPartRequest = request as UploadPartRequest;

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
                    EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(initiateMultiPartUploadRequest, instructions, EncryptionClient);
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

            if (request.IsLastPart == false)
            {
                if (contextForEncryption.IsFinalPart)
                    throw new AmazonClientException("Last part has already been processed, cannot upload this as the last part");

                if (request.PartNumber < contextForEncryption.PartNumber)
                    throw new AmazonClientException($"Upload Parts must be in correct sequence. Request part number {request.PartNumber} must be >= to {contextForEncryption.PartNumber}");

                if (contextForEncryption.CryptoStream == null)
                {
                    request.InputStream = EncryptionUtils.EncryptUploadPartRequestUsingInstructionsV2(request.InputStream, instructions);
                }
                else
                {
                    request.InputStream = contextForEncryption.CryptoStream;
                }
                contextForEncryption.PartNumber = request.PartNumber;
            }
            else
            {
                if (contextForEncryption.CryptoStream == null)
                {
                    request.InputStream = EncryptionUtils.EncryptUploadPartRequestUsingInstructionsV2(request.InputStream, instructions);
                }
                else
                {
                    request.InputStream = contextForEncryption.CryptoStream;
                }
                contextForEncryption.IsFinalPart = true;
            }
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(AmazonS3EncryptionClient.S3CryptoStream, request.InputStream);

        }
    }
}
