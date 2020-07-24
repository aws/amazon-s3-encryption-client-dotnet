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
using Amazon.Extensions.S3.Encryption.Util;
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
        /// Construct an instance SetupEncryptionHandlerV2.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupDecryptionHandlerV2(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

        /// <inheritdoc/>
        protected override GetObjectRequest GetInstructionFileRequest(GetObjectResponse getObjectResponse)
        {
            return EncryptionUtils.GetInstructionFileRequestV2(getObjectResponse);
        }

        /// <inheritdoc/>
        protected override bool KMSEnvelopeKeyIsPresent(IExecutionContext executionContext,
            out byte[] encryptedKMSEnvelopeKey, out Dictionary<string, string> encryptionContext)
        {
            var response = executionContext.ResponseContext.Response;
            var getObjectResponse = response as GetObjectResponse;
            encryptedKMSEnvelopeKey = null;
            encryptionContext = null;

            if (getObjectResponse != null)
            {
                var metadata = getObjectResponse.Metadata;
                EncryptionUtils.EnsureSupportedAlgorithms(metadata);

                var base64EncodedEncryptedKmsEnvelopeKey = metadata[EncryptionUtils.XAmzKeyV2];
                if (base64EncodedEncryptedKmsEnvelopeKey != null)
                {
                    var wrapAlgorithm = metadata[EncryptionUtils.XAmzWrapAlg];
                    if (!(EncryptionUtils.XAmzWrapAlgKmsContextValue.Equals(wrapAlgorithm) || EncryptionUtils.XAmzWrapAlgKmsValue.Equals(wrapAlgorithm)))
                    {
                        return false;
                    }
                    
                    encryptedKMSEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedKmsEnvelopeKey);
                    if (EncryptionUtils.XAmzWrapAlgKmsValue.Equals(wrapAlgorithm))
                    {
                        encryptionContext = EncryptionUtils.GetMaterialDescriptionFromMetaData(metadata);
                    }
                    else
                    {
                        encryptionContext = EncryptionUtils.GenerateEncryptionContextForKMS(EncryptionUtils.GetMaterialDescriptionFromMetaData(metadata));
                    }

                    return true;
                }
            }
            return false;
        }

        /// <inheritdoc/>
        protected override void DecryptObjectUsingInstructionFile(GetObjectResponse response, GetObjectResponse instructionFileResponse)
        {
            // Create an instruction object from the instruction file response
            var instructions = EncryptionUtils.BuildInstructionsUsingInstructionFileV2(instructionFileResponse, EncryptionClient.EncryptionMaterials);

            if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.CekAlgorithm))
            {
                // Decrypt the object with V2 instructions
                EncryptionUtils.DecryptObjectUsingInstructionsV2(response, instructions);
            }
            else
            {
                // Decrypt the object with V1 instructions
                EncryptionUtils.DecryptObjectUsingInstructions(response, instructions);
            }
        }

        /// <inheritdoc/>
        protected override void DecryptObjectUsingMetadata(GetObjectResponse objectResponse, byte[] decryptedEnvelopeKeyKMS)
        {
            // Create an instruction object from the object metadata
            EncryptionInstructions instructions = EncryptionUtils.BuildInstructionsFromObjectMetadata(objectResponse, EncryptionClient.EncryptionMaterials, decryptedEnvelopeKeyKMS);

            if (decryptedEnvelopeKeyKMS != null)
            {
                if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(objectResponse.Metadata[EncryptionUtils.XAmzCekAlg])
                    && EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.CekAlgorithm))
                {
                    // Decrypt the object with V2 instruction
                    EncryptionUtils.DecryptObjectUsingInstructionsV2(objectResponse, instructions);
                }
                else if (EncryptionUtils.XAmzAesCbcPaddingCekAlgValue.Equals(objectResponse.Metadata[EncryptionUtils.XAmzCekAlg]))
                {
                    // Decrypt the object with V1 instruction
                    EncryptionUtils.DecryptObjectUsingInstructions(objectResponse, instructions);
                }
                else
                {
                    throw new AmazonS3Exception($"CEK algorithm in {EncryptionUtils.XAmzCekAlg} & {EncryptionUtils.XAmzEncryptionContextCekAlg} must be same." +
                                                $" ${EncryptionClient.GetType().Name} only supports ${EncryptionUtils.XAmzAesGcmCekAlgValue} for KMS mode.");
                }
            }
            else if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(objectResponse.Metadata[EncryptionUtils.XAmzCekAlg]))
            {
                // Decrypt the object with V2 instruction
                EncryptionUtils.DecryptObjectUsingInstructionsV2(objectResponse, instructions);
            }
            // It is safe to assume, this is either non KMS encryption with V1 client or AES CBC
            // We don't need to check cek algorithm to be AES CBC, because non KMS encryption with V1 client doesn't set it
            else
            {
                EncryptionUtils.DecryptObjectUsingInstructions(objectResponse, instructions);
            }
        }

#if BCL
        /// <inheritdoc/>
        protected override void CompleteMultipartUpload(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];

            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV2(context, EncryptionClient.EncryptionMaterials);
                var instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV2(completeMultiPartUploadRequest, instructions);
                EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.Remove(completeMultiPartUploadRequest.UploadId);
        }
#endif

#if AWS_ASYNC_API
        /// <inheritdoc/>
        protected override async System.Threading.Tasks.Task CompleteMultipartUploadAsync(CompleteMultipartUploadRequest completeMultiPartUploadRequest)
        {
            UploadPartEncryptionContext context = EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];

            if (context.StorageMode == CryptoStorageMode.InstructionFile)
            {
                var instructions = EncryptionUtils.BuildEncryptionInstructionsForInstructionFileV2(context, EncryptionClient.EncryptionMaterials);
                PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequestV2(completeMultiPartUploadRequest, instructions);
                await EncryptionClient.S3ClientForInstructionFile.PutObjectAsync(instructionFileRequest).ConfigureAwait(false);
            }

            //Clear Context data since encryption is completed
            EncryptionClient.CurrentMultiPartUploadKeys.Remove(completeMultiPartUploadRequest.UploadId);
        }
#endif

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
