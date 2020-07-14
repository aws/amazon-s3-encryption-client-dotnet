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
using System.Collections.Generic;
using Amazon.Runtime;
using Amazon.S3.Model;
using ThirdParty.Json.LitJson;

namespace Amazon.S3.Encryption.Internal
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

        ///<inheritdoc/>
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

                    var cekAlgFromMetadata = GetValueFromMetadata(metadata, EncryptionUtils.XAmzEncryptionContextCekAlg);
                    if (cekAlgFromMetadata != null)
                    {
                        encryptionContext[EncryptionUtils.XAmzEncryptionContextCekAlg] = cekAlgFromMetadata;
                    }
                    else
                    {
                        // Cek algorithm doesn't exist in V1 client, therefore, include KMS ID for compatibility
                        var kmsKeyIdFromMetadata = GetValueFromMetadata(metadata, EncryptionUtils.KMSCmkIDKey);
                        if (kmsKeyIdFromMetadata != null)
                        {
                            encryptionContext[EncryptionUtils.KMSCmkIDKey] = kmsKeyIdFromMetadata;
                        }
                    }

                    return true;
                }
            }
            return false;
        }
        
        private static string GetValueFromMetadata(MetadataCollection metadata, string key)
        {
            var materialDescriptionJsonString = metadata[EncryptionUtils.XAmzMatDesc];
            if (materialDescriptionJsonString == null)
            {
                return null;
            }

            JsonData materialDescriptionJsonData;
            try
            {
                materialDescriptionJsonData = JsonMapper.ToObject(materialDescriptionJsonString);
            }
            catch (JsonException e)
            {
                return null;
            }

            JsonData valueData;
            try
            {
                valueData = materialDescriptionJsonData[key];
            }
            catch (JsonException e)
            {
                return null;
            }

            if (valueData == null)
            {
                return null;
            }

            return valueData.ToString();
        }

        ///<inheritdoc/>
        protected override void DecryptObjectUsingInstructionFile(GetObjectResponse response, GetObjectResponse instructionFileResponse)
        {
            // Create an instruction object from the instruction file response
            EncryptionInstructions instructions;
            if (EncryptionUtils.XAmzWrapAlgRsaOaepSha1.Equals(instructionFileResponse.Metadata[EncryptionUtils.XAmzWrapAlg]))
            {
                // Decrypt the object with V2 instructions
                instructions = EncryptionUtils.BuildInstructionsUsingInstructionFile(
                    instructionFileResponse, EncryptionClient.EncryptionMaterials, EncryptionUtils.DecryptNonKmsEnvelopeKeyV2);
            }
            else
            {
                // Decrypt the object with V1 instructions
                instructions = EncryptionUtils.BuildInstructionsUsingInstructionFile(
                    instructionFileResponse, EncryptionClient.EncryptionMaterials, EncryptionUtils.DecryptNonKMSEnvelopeKey);
            }

            if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(
                instructionFileResponse.Metadata[EncryptionUtils.XAmzCekAlg]))
            {
                // Decrypt the object with V2 instructions
                var tagSize = int.Parse(instructionFileResponse.Metadata[EncryptionUtils.XAmzTagLen]);
                EncryptionUtils.DecryptObjectUsingInstructionsV2(response, instructions, tagSize);
            }
            else
            {
                // Decrypt the object with V1 instructions
                EncryptionUtils.DecryptObjectUsingInstructions(response, instructions);
            }
        }

        ///<inheritdoc/>
        protected override void DecryptObjectUsingMetadata(GetObjectResponse objectResponse, byte[] decryptedEnvelopeKeyKMS)
        {
            // Create an instruction object from the object metadata
            EncryptionInstructions instructions;
            if (EncryptionUtils.XAmzWrapAlgRsaOaepSha1.Equals(objectResponse.Metadata[EncryptionUtils.XAmzWrapAlg]))
            {
                // Decrypt the object with V2 instruction
                instructions = EncryptionUtils.BuildInstructionsFromObjectMetadata(objectResponse, this.EncryptionClient.EncryptionMaterials, 
                    decryptedEnvelopeKeyKMS, EncryptionUtils.DecryptNonKmsEnvelopeKeyV2);
            }
            else
            {
                // Decrypt the object with V1 instruction
                instructions = EncryptionUtils.BuildInstructionsFromObjectMetadata(objectResponse, this.EncryptionClient.EncryptionMaterials, 
                    decryptedEnvelopeKeyKMS, EncryptionUtils.DecryptNonKMSEnvelopeKey);
            }

            if (decryptedEnvelopeKeyKMS != null)
            {
                if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(objectResponse.Metadata[EncryptionUtils.XAmzCekAlg]) 
                    && instructions.MaterialsDescription.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg)
                    && EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.MaterialsDescription[EncryptionUtils.XAmzEncryptionContextCekAlg]))
                {
                    // Decrypt the object with V2 instruction
                    var tagSize = int.Parse(objectResponse.Metadata[EncryptionUtils.XAmzTagLen]);
                    EncryptionUtils.DecryptObjectUsingInstructionsV2(objectResponse, instructions, tagSize);
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
                var tagSize = int.Parse(objectResponse.Metadata[EncryptionUtils.XAmzTagLen]);
                EncryptionUtils.DecryptObjectUsingInstructionsV2(objectResponse, instructions, tagSize);
            }
            // It is safe to assume, this is either non KMS encryption with V1 client or AES CBC
            // We don't need to check cek algorithm to be AES CBC, because non KMS encryption with V1 client doesn't set it
            else
            {
                EncryptionUtils.DecryptObjectUsingInstructions(objectResponse, instructions);
            }
        }
    }
}
