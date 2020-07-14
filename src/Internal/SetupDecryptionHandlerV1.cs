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
using System.Globalization;
using System.Linq;
using System.Text;
using Amazon.Runtime;
using Amazon.S3.Model;
using System.IO;

using Amazon.S3.Util;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.Util;
using Amazon.Runtime.SharedInterfaces;
using Amazon.S3.Internal;
using ThirdParty.Json.LitJson;

namespace Amazon.S3.Encryption.Internal
{
    /// <summary>
    /// Custom the pipeline handler to decrypt objects for AmazonS3EncryptionClient.
    /// </summary>
    public class SetupDecryptionHandlerV1 : SetupDecryptionHandler
    {
        private const string KMSKeyIDMetadataMessage = "Unable to determine the KMS key ID from the object metadata.";

        /// <summary>
        /// Construct an instance SetupEncryptionHandlerV1.
        /// </summary>
        /// <param name="encryptionClient">Encryption client used to put and get objects</param>
        public SetupDecryptionHandlerV1(AmazonS3EncryptionClientBase encryptionClient) : base(encryptionClient)
        {
        }

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
                    if (!EncryptionUtils.XAmzWrapAlgKmsValue.Equals(wrapAlgorithm))
                    {
                        return false;
                    }
                    
                    encryptedKMSEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedKmsEnvelopeKey);
                    encryptionContext = new Dictionary<string, string>();
                    var kmsKeyIdFromMetadata = GetKmsKeyIdFromMetadata(metadata);
                    encryptionContext[EncryptionUtils.KMSCmkIDKey] = kmsKeyIdFromMetadata;

                    return true;
                }
            }
            return false;
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
                JsonData materialDescriptionJsonData;
                try
                {
                    materialDescriptionJsonData = JsonMapper.ToObject(materialDescriptionJsonString);
                }
                catch (JsonException e)
                {
                    throw new InvalidDataException($"{KMSKeyIDMetadataMessage} The key '{EncryptionUtils.XAmzMatDesc}' does not contain valid JSON.", e);
                }

                JsonData kmsKeyIDJsonData;
                try
                {
                    kmsKeyIDJsonData = materialDescriptionJsonData[EncryptionUtils.KMSCmkIDKey];
                }
                catch (JsonException e)
                {
                    throw new InvalidDataException($"{KMSKeyIDMetadataMessage} The key '{EncryptionUtils.KMSCmkIDKey}' is does not contain valid JSON.", e);
                }

                if (kmsKeyIDJsonData == null)
                {
                    throw new InvalidDataException($"{KMSKeyIDMetadataMessage} The key '{kmsKeyIDJsonData}' is missing from the material description.");
                }

                return kmsKeyIDJsonData.ToString();
            }
        }

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="instructionFileResponse">
        /// The getObject response of InstructionFile.
        /// </param>
        /// <param name="response">
        /// The getObject response whose contents are to be decrypted.
        /// </param>
        protected void DecryptObjectUsingInstructionFile(GetObjectResponse response, GetObjectResponse instructionFileResponse)
        {
            // Create an instruction object from the instruction file response
            EncryptionInstructions instructions = EncryptionUtils.BuildInstructionsUsingInstructionFile(
                instructionFileResponse, this.EncryptionClient.EncryptionMaterials, EncryptionUtils.DecryptNonKMSEnvelopeKey);

            // Decrypt the object with the instructions
            EncryptionUtils.DecryptObjectUsingInstructions(response, instructions);
        }

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="objectResponse">
        /// The getObject response whose contents are to be decrypted.
        /// </param>
        /// <param name="decryptedEnvelopeKeyKMS">
        /// The decrypted envelope key to be use if KMS key wrapping is being used.  Or null if non-KMS key wrapping is being used.
        /// </param>
        protected void DecryptObjectUsingMetadata(GetObjectResponse objectResponse, byte[] decryptedEnvelopeKeyKMS)
        {
            // Create an instruction object from the object metadata
            EncryptionInstructions instructions = EncryptionUtils.BuildInstructionsFromObjectMetadata(
                objectResponse, this.EncryptionClient.EncryptionMaterials, decryptedEnvelopeKeyKMS, EncryptionUtils.DecryptNonKMSEnvelopeKey);

            // Decrypt the object with the instruction
            EncryptionUtils.DecryptObjectUsingInstructions(objectResponse, instructions);
        }
  
        ///<inheritdoc/>
        protected override void PostInvokeSynchronous(IExecutionContext executionContext, byte[] decryptedEnvelopeKeyKMS)
        {
            var request = executionContext.RequestContext.Request;
            var response = executionContext.ResponseContext.Response;

            var initiateMultiPartUploadRequest = request.OriginalRequest as InitiateMultipartUploadRequest;
            var initiateMultiPartResponse = response as InitiateMultipartUploadResponse;
            if (initiateMultiPartResponse != null)
            {
                byte[] encryptedEnvelopeKey = initiateMultiPartUploadRequest.EncryptedEnvelopeKey;
                byte[] envelopeKey = initiateMultiPartUploadRequest.EnvelopeKey;
                byte[] iv = initiateMultiPartUploadRequest.IV;

                UploadPartEncryptionContext contextForEncryption = new UploadPartEncryptionContext();
                contextForEncryption.StorageMode = initiateMultiPartUploadRequest.StorageMode;
                contextForEncryption.EncryptedEnvelopeKey = encryptedEnvelopeKey;
                contextForEncryption.EnvelopeKey = envelopeKey;
                contextForEncryption.NextIV = iv;
                contextForEncryption.FirstIV = iv;
                contextForEncryption.PartNumber = 0;

                //Add context for encryption of next part
                this.EncryptionClient.CurrentMultiPartUploadKeys.Add(initiateMultiPartResponse.UploadId, contextForEncryption);
            }

            var uploadPartRequest = request.OriginalRequest as UploadPartRequest;
            var uploadPartResponse = response as UploadPartResponse;
            if (uploadPartResponse != null)
            {
                string uploadID = uploadPartRequest.UploadId;
                UploadPartEncryptionContext encryptedUploadedContext = null;

                if (!this.EncryptionClient.CurrentMultiPartUploadKeys.TryGetValue(uploadID, out encryptedUploadedContext))
                    throw new AmazonS3Exception("Encryption context for multi part upload not found");

                if (!uploadPartRequest.IsLastPart)
                {
                    object stream = null;

                    if (!((Amazon.Runtime.Internal.IAmazonWebServiceRequest)uploadPartRequest).RequestState.TryGetValue(AmazonS3EncryptionClient.S3CryptoStream, out stream))
                        throw new AmazonS3Exception("Cannot retrieve S3 crypto stream from request state, hence cannot get Initialization vector for next uploadPart ");

                    var encryptionStream = stream as AESEncryptionUploadPartStream;
                    if (encryptionStream != null)
                    {
                        encryptedUploadedContext.NextIV = encryptionStream.InitializationVector;
                    }
                }
            }

            var getObjectResponse = response as GetObjectResponse;
            if (getObjectResponse != null)
            {
                if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse))
                {
                    DecryptObjectUsingMetadata(getObjectResponse, decryptedEnvelopeKeyKMS);
                }
                else
                {
                    GetObjectResponse instructionFileResponse = null;
                    try
                    {
                        GetObjectRequest instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse);
                        instructionFileResponse = this.EncryptionClient.S3ClientForInstructionFile.GetObject(instructionFileRequest);
                    }
                    catch (AmazonServiceException ace)
                    {
                        throw new AmazonServiceException(string.Format(CultureInfo.InvariantCulture, "Unable to decrypt data for object {0} in bucket {1}",
                            getObjectResponse.Key, getObjectResponse.BucketName), ace);
                    }

                    if (EncryptionUtils.IsEncryptionInfoInInstructionFile(instructionFileResponse))
                    {
                        DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
                    }
                }
            }

            var completeMultiPartUploadRequest = request.OriginalRequest as CompleteMultipartUploadRequest;
            var completeMultipartUploadResponse = response as CompleteMultipartUploadResponse;
            if (completeMultipartUploadResponse != null)
            {
                UploadPartEncryptionContext context = this.EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];

                if (context.StorageMode == CryptoStorageMode.InstructionFile)
                {
                    byte[] envelopeKey = context.EnvelopeKey;
                    byte[] iv = context.FirstIV;
                    byte[] encryptedEnvelopeKey = context.EncryptedEnvelopeKey;
                    EncryptionInstructions instructions = new EncryptionInstructions(EncryptionClient.EncryptionMaterials.MaterialsDescription, envelopeKey, encryptedEnvelopeKey, iv);

                    PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(completeMultiPartUploadRequest, instructions);

                    this.EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
                }

                //Clear Context data since encryption is completed
                this.EncryptionClient.CurrentMultiPartUploadKeys.Remove(completeMultiPartUploadRequest.UploadId);
            }

            var abortMultipartUploadRequest = request.OriginalRequest as AbortMultipartUploadRequest;
            var abortMultipartUploadResponse = response as AbortMultipartUploadResponse;
            if (abortMultipartUploadResponse != null)
            {
                //Clear Context data since encryption is aborted
                EncryptionClient.CurrentMultiPartUploadKeys.Remove(abortMultipartUploadRequest.UploadId);
            }
        }
    }
}
