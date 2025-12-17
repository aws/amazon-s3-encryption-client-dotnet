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
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.Runtime;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3 for AmazonS3EncryptionClientV4.
    /// </summary>
    public class SetupEncryptionHandlerV4 : SetupEncryptionHandler
    {
        /// <summary>
        /// Encryption material containing cryptographic configuration information
        /// </summary>
        internal EncryptionMaterialsV4 EncryptionMaterials =>
            (EncryptionMaterialsV4)EncryptionClient.EncryptionMaterials;
        
        /// <summary>
        /// Crypto configuration of the encryption client
        /// </summary>
        internal AmazonS3CryptoConfigurationV4 CryptoConfiguration => EncryptionClient.S3CryptoConfig as AmazonS3CryptoConfigurationV4;

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV4.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandlerV4(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
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
            if (uploadPartRequest == null)
            {
                return;
            }
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
        
        /// <inheritdoc/>
        protected override PutObjectRequest GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            // Encrypt the object data with the instruction
            putObjectRequest.InputStream = IsV2Schema() ? EncryptionUtils.EncryptRequestUsingAesGcm(putObjectRequest.InputStream, instructions): 
                EncryptionUtils.EncryptRequestUsingAesGcmWithKeyCommitment(putObjectRequest.InputStream, instructions);
            
            // Create request for uploading instruction file 
            PutObjectRequest instructionFileRequest = IsV2Schema() ?
                //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
                EncryptionUtils.CreateInstructionFileRequestV2(putObjectRequest, instructions) : 
                //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
                EncryptionUtils.CreateInstructionFileRequestV3(putObjectRequest, instructions);
            
            if (IsV2Schema())
            {
                // V2 object does not request UnencryptedContentLength but .NET was adding it. So, this was left as-is
                EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);
            }
            
            return instructionFileRequest;
        }
        
#if NETFRAMEWORK
        /// <inheritdoc/>
        protected override EncryptionInstructions GenerateInstructions(IExecutionContext executionContext)
        {
            var algorithmSuit = GetAlgorithmSuit();
            EncryptionInstructions instructions = null;
            if (IsV2Schema())
                EncryptionContextUtils.AddReservedKeywordToEncryptionContextV2(EncryptionMaterials.EncryptionContext);
            else
                EncryptionContextUtils.AddReservedKeywordToEncryptionContextV3(EncryptionMaterials.EncryptionContext);

            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = IsV2Schema() ?
                    EncryptionUtils.GenerateInstructionsForKMSMaterialsV2(EncryptionClient.KMSClient, EncryptionMaterials.KMSKeyID, EncryptionMaterials.KmsType, EncryptionMaterials.EncryptionContext, algorithmSuit):
                    EncryptionUtils.GenerateInstructionsForKMSMaterialsV3(EncryptionClient.KMSClient, EncryptionMaterials, algorithmSuit);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = IsV2Schema() ?
                    EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials.AsymmetricProvider, EncryptionMaterials.AsymmetricProviderType,
                        EncryptionMaterials.SymmetricProvider, EncryptionMaterials.SymmetricProviderType, EncryptionMaterials.MaterialsDescription, algorithmSuit):
                    EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV3(EncryptionMaterials, algorithmSuit);
            }

            return instructions;
        }
#endif
        
        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsAsync(IExecutionContext executionContext)
        {
            var algorithmSuit = GetAlgorithmSuit();
            EncryptionInstructions instructions = null;
            if (IsV2Schema())
                EncryptionContextUtils.AddReservedKeywordToEncryptionContextV2(EncryptionMaterials.EncryptionContext);
            else
                EncryptionContextUtils.AddReservedKeywordToEncryptionContextV3(EncryptionMaterials.EncryptionContext);

            if (NeedToGenerateKMSInstructions(executionContext))
            {
                instructions = IsV2Schema() ? 
                    await EncryptionUtils.GenerateInstructionsForKMSMaterialsV2Async(EncryptionClient.KMSClient, EncryptionMaterials.KMSKeyID, EncryptionMaterials.KmsType, EncryptionMaterials.EncryptionContext, algorithmSuit)
                        .ConfigureAwait(false):
                    await EncryptionUtils.GenerateInstructionsForKmsMaterialsV3Async(EncryptionClient.KMSClient, EncryptionMaterials, algorithmSuit)
                        .ConfigureAwait(false);
            }

            if (instructions == null && NeedToGenerateInstructions(executionContext))
            {
                instructions = IsV2Schema() ? 
                        EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials.AsymmetricProvider, EncryptionMaterials.AsymmetricProviderType,
                            EncryptionMaterials.SymmetricProvider, EncryptionMaterials.SymmetricProviderType, EncryptionMaterials.MaterialsDescription, algorithmSuit):
                        EncryptionUtils.GenerateInstructionsForNonKmsMaterialsV3(EncryptionMaterials, algorithmSuit);
            }

            return instructions;
        }
        
        /// <inheritdoc/>
        protected override void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions)
        {
            if (IsV2Schema())
            {
                // UnencryptedContentLength should only be added for V1 format, but
                // it is added to align with what V2 client of S3EC .NET does
                EncryptionUtils.AddUnencryptedContentLengthToMetadata(putObjectRequest);
                
                putObjectRequest.InputStream =
                    EncryptionUtils.EncryptRequestUsingAesGcm(putObjectRequest.InputStream, instructions);
                //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
                EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(putObjectRequest, instructions);
            }
            else
            {
                putObjectRequest.InputStream =
                    EncryptionUtils.EncryptRequestUsingAesGcmWithKeyCommitment(putObjectRequest.InputStream, instructions);
                //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
                EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV3(putObjectRequest, instructions);
            }
        }
        
        /// <inheritdoc/>
        protected override void GenerateInitiateMultiPartUploadRequest(EncryptionInstructions instructions, InitiateMultipartUploadRequest initiateMultiPartUploadRequest, bool useKmsKeyWrapping)
        {
            ValidateConfigAndMaterials();
            
            var algorithmSuit = GetAlgorithmSuit();
            var storageMode = EncryptionClient.S3CryptoConfig.StorageMode;
            if (!IsV2Schema())
            {
                EncryptionUtils.ValidateMessageId(instructions.MessageId, algorithmSuit);
                //= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
                //= type=implication
                //# The derived key commitment value MUST be set or returned from the encryption process such that it can be included in the content metadata.
                instructions.KeyCommitment = EncryptionUtils.DeriveKeyCommitment(instructions);
            }
            
            if (storageMode == CryptoStorageMode.ObjectMetadata)
            {
                if (IsV2Schema())
                {
                    EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(initiateMultiPartUploadRequest, instructions);
                }
                else
                {
                    EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV3(initiateMultiPartUploadRequest, instructions);
                }
            }

            if (storageMode == CryptoStorageMode.InstructionFile && !IsV2Schema())
            {
                var base64EncodedKeyCommitment = Convert.ToBase64String(instructions.KeyCommitment);
                var base64EncodedMessageId = Convert.ToBase64String(instructions.MessageId);
                initiateMultiPartUploadRequest.Metadata.Add(ContentMetaDataV3Utils.ContentCipherV3, EncryptionUtils.XAmzCekAlgAes256GcmHkdfSha512CommitKey);
                initiateMultiPartUploadRequest.Metadata.Add(ContentMetaDataV3Utils.KeyCommitmentV3, base64EncodedKeyCommitment);
                initiateMultiPartUploadRequest.Metadata.Add(ContentMetaDataV3Utils.MessageIdV3, base64EncodedMessageId);
            }

            var firstIv = IsV2Schema() ? instructions.InitializationVector : instructions.MessageId;
            var nextIv = firstIv;
            var context = new UploadPartEncryptionContext
                {
                    StorageMode = storageMode,
                    EncryptedEnvelopeKey = instructions.EncryptedEnvelopeKey,
                    EnvelopeKey = instructions.EnvelopeKey,
                    FirstIV = firstIv,
                    NextIV = nextIv,
                    PartNumber = 0,
                    AlgorithmSuite = instructions.AlgorithmSuite,
                    WrapAlgorithm = instructions.WrapAlgorithm,
                };
                
            if (!IsV2Schema())
                context.KeyCommitment = instructions.KeyCommitment;
            EncryptionClient.AllMultiPartUploadRequestContexts[initiateMultiPartUploadRequest] = context;
        }
        
        /// <inheritdoc/>
        protected override void GenerateEncryptedUploadPartRequest(UploadPartRequest request)
        {
            var algorithmSuit = GetAlgorithmSuit();
            string uploadID = request.UploadId;

            var contextForEncryption = this.EncryptionClient.CurrentMultiPartUploadKeys[uploadID];
            var envelopeKey = contextForEncryption.EnvelopeKey;
            var iv = contextForEncryption.NextIV;
            EncryptionInstructions instructions;
            if (!IsV2Schema())
            {
                var keyCommitment = contextForEncryption.KeyCommitment;
                instructions = new EncryptionInstructions(EncryptionMaterials.MaterialsDescription, EncryptionMaterials.EncryptionContext, 
                    envelopeKey, contextForEncryption.EncryptedEnvelopeKey, contextForEncryption.WrapAlgorithm, iv, keyCommitment, algorithmSuit);
            }
            else
            {
                instructions = new EncryptionInstructions(EncryptionMaterials.MaterialsDescription, envelopeKey, iv);
            }
            
            //= ../specification/s3-encryption/client.md#optional-api-operations
            //# - UploadPart MUST encrypt each part.
            if (request.IsLastPart == false)
            {
                if (contextForEncryption.IsFinalPart)
                    throw new AmazonClientException("Last part has already been processed, cannot upload this as the last part");
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //# - Each part MUST be encrypted in sequence.
                if (request.PartNumber < contextForEncryption.PartNumber)
                    throw new AmazonClientException($"Upload Parts must be in correct sequence. Request part number {request.PartNumber} must be >= to {contextForEncryption.PartNumber}");

                UpdateRequestInputStream(request, contextForEncryption, instructions, IsV2Schema());
                contextForEncryption.PartNumber = request.PartNumber;
            }
            else
            {
                UpdateRequestInputStream(request, contextForEncryption, instructions, IsV2Schema());
                contextForEncryption.IsFinalPart = true;
            }
            ((Amazon.Runtime.Internal.IAmazonWebServiceRequest)request).RequestState.Add(Constants.S3CryptoStreamRequestState, request.InputStream);

        }
        
        private static void UpdateRequestInputStream(UploadPartRequest request, UploadPartEncryptionContext contextForEncryption, EncryptionInstructions instructions, Boolean isV2Schema)
        {
            if (contextForEncryption.CryptoStream == null)
            {
                request.InputStream = isV2Schema ?
                    EncryptionUtils.EncryptUploadPartRequestUsingAesGcm(request.InputStream, instructions): 
                    EncryptionUtils.EncryptRequestUsingAesGcmWithKeyCommitment(request.InputStream, instructions);
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

        private bool IsV2Schema()
        {
            // ContentEncryptionAlgorithm is either AesGcm or AesGcmWithCommitment;
            // For the scope of this class, if it is `AesGcm`, then a Message Format V2 is being created; otherwise, a Message Format V3 is being created.
            return CryptoConfiguration.ContentEncryptionAlgorithm == ContentEncryptionAlgorithm.AesGcm;
        }

        private AlgorithmSuite GetAlgorithmSuit()
        {
            return IsV2Schema()? AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf: AlgorithmSuite
                .AlgAes256GcmHkdfSha512CommitKey;
        }
    }
}