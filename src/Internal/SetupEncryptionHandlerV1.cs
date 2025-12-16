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

 using Amazon.Runtime;
 using Amazon.S3.Model;
using Amazon.Extensions.S3.Encryption.Util;

 namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV1.
    /// </summary>
    public class SetupEncryptionHandlerV1 : SetupEncryptionHandler
    {
        /// <summary>
        /// Algorithm suite used for encryption by S3 encryption client V1
        /// </summary>
        private readonly AlgorithmSuite _aes256CbcIv16NoKdf = AlgorithmSuite.AlgAes256CbcIv16NoKdf;
        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterials EncryptionMaterials => (EncryptionMaterials)EncryptionClient.EncryptionMaterials;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV1.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandlerV1(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

#if NETFRAMEWORK
        /// <inheritdoc/>
        protected override EncryptionInstructions GenerateInstructions(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;

            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForKMSMaterials(EncryptionClient.KMSClient, EncryptionMaterials, _aes256CbcIv16NoKdf);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKMSMaterials(EncryptionMaterials, _aes256CbcIv16NoKdf);
            }

            return instructions;
        }
#endif

        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsAsync(IExecutionContext executionContext)
        {
            EncryptionInstructions instructions = null;
            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = await EncryptionUtils.GenerateInstructionsForKMSMaterialsAsync(
                    EncryptionClient.KMSClient, EncryptionMaterials, _aes256CbcIv16NoKdf).ConfigureAwait(false);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = EncryptionUtils.GenerateInstructionsForNonKMSMaterials(EncryptionMaterials, _aes256CbcIv16NoKdf);
            }

            return instructions;
        }

        /// <inheritdoc/>
        protected override void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstruction(putObjectRequest.InputStream, instructions);
            
            // Update the metadata
            
            // UpdateMetadataWithEncryptionInstructions only uses V1 format when using non KMS Material.
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=exception
            //= reason= useV2Metadata is true on kms wrapping key. So, S3EC .NET uses v2 metadata on KMS in V1 object and v1 metadata on non KMS in v1 object. 
            //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
            
            // Since the code path is in V1 encryption handler, it is assumed the content encryption is ALG_AES_256_CBC_IV16_NO_KDF
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
            var useV2Metadata = EncryptionMaterials.KMSKeyID != null;
            EncryptionUtils.UpdateMetadataWithEncryptionInstructions(putObjectRequest, instructions, 
                useV2Metadata);
        }

        /// <inheritdoc/>
        protected override PutObjectRequest GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
            EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);

            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = EncryptionUtils.EncryptRequestUsingInstruction(putObjectRequest.InputStream, instructions);

            // Create request for uploading instruction file 
            
            // Since the code path is in V1 encryption handler, it is assumed the content encryption is ALG_AES_256_CBC_IV16_NO_KDF
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=exception
            //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
            PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(putObjectRequest, instructions);

            return instructionFileRequest;
        }

        /// <inheritdoc/>
        protected override void GenerateInitiateMultiPartUploadRequest(EncryptionInstructions instructions, InitiateMultipartUploadRequest initiateMultiPartUploadRequest, bool useKMSKeyWrapping)
        {
            ValidateConfigAndMaterials();
            if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
            {
                EncryptionUtils.UpdateMetadataWithEncryptionInstructions(initiateMultiPartUploadRequest, instructions, useKMSKeyWrapping);
            }

            var context = new UploadPartEncryptionContext
            {
                StorageMode = EncryptionClient.S3CryptoConfig.StorageMode,
                EncryptedEnvelopeKey = instructions.EncryptedEnvelopeKey,
                EnvelopeKey = instructions.EnvelopeKey,
                NextIV = instructions.InitializationVector,
                FirstIV = instructions.InitializationVector,
                PartNumber = 0,
                WrapAlgorithm = instructions.WrapAlgorithm,
                AlgorithmSuite = instructions.AlgorithmSuite,
            };

            EncryptionClient.AllMultiPartUploadRequestContexts[initiateMultiPartUploadRequest] = context;
        }

        /// <inheritdoc/>
        protected override void GenerateEncryptedUploadPartRequest(UploadPartRequest request)
        {
            string uploadID = request.UploadId;
            
            UploadPartEncryptionContext contextForEncryption = this.EncryptionClient.CurrentMultiPartUploadKeys[uploadID];
            byte[] envelopeKey = contextForEncryption.EnvelopeKey;
            byte[] IV = contextForEncryption.NextIV;

            EncryptionInstructions instructions = new EncryptionInstructions(EncryptionMaterials.MaterialsDescription, envelopeKey, IV);
            
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
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(Constants.S3CryptoStreamRequestState, request.InputStream);
        }
    }
}
