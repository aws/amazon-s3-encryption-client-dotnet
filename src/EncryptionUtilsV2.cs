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
using System.IO;
using System.Security.Cryptography;
using Amazon.S3.Model;
using Amazon.Runtime.Internal.Util;
using Amazon.Runtime;
using ThirdParty.Json.LitJson;
using System.Collections.Generic;
using System.Linq;
using Amazon.Runtime.SharedInterfaces;

namespace Amazon.S3.Encryption
{
    /// <summary>
    /// The EncryptionUtils class encrypts and decrypts data stored in S3.
    /// It can be used to prepare requests for encryption before they are stored in S3
    /// and to decrypt objects that are retrieved from S3.
    /// </summary>
    internal static partial class EncryptionUtils
    {
        /// <summary>
        /// Decrypt the envelope key with RSA-OAEP-SHA1 
        /// </summary>
        /// <param name="encryptedEnvelopeKey">Encrypted envelope key</param>
        /// <param name="materials">Encryption materials needed to decrypt the encrypted envelope key</param>
        /// <returns></returns>
        internal static byte[] DecryptNonKmsEnvelopeKeyV2(byte[] encryptedEnvelopeKey, EncryptionMaterials materials)
        {
            var rsaCryptoServiceProvider = materials.AsymmetricProvider as RSACryptoServiceProvider;
            return rsaCryptoServiceProvider.Decrypt(encryptedEnvelopeKey, true);
        }

        /// <summary>
        /// Returns an updated stream where the stream contains the encrypted object contents.
        /// The specified instruction will be used to encrypt data.
        /// </summary>
        /// <param name="toBeEncrypted">
        /// The stream whose contents are to be encrypted.
        /// </param>
        /// <param name="instructions">
        /// The instruction that will be used to encrypt the object data.
        /// </param>
        /// <returns>
        /// Encrypted stream, i.e input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptRequestUsingInstructionV2(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            Stream gcmEncryptStream = new AesGcmEncryptStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagLength);
            return gcmEncryptStream;
        }

        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the AsymmetricProvider or SymmetricProvider set.
        /// </summary>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt data.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterials materials)
        {
            var rsaCryptoServiceProvider = materials.AsymmetricProvider as RSACryptoServiceProvider;
            var aesObject = Aes.Create();
            var encryptedEnvelopeKey = rsaCryptoServiceProvider.Encrypt(aesObject.Key, true);
            return new EncryptionInstructions(materials.MaterialsDescription, aesObject.Key, encryptedEnvelopeKey, aesObject.IV);
        }

        /// <summary>
        /// Update the request's ObjectMetadata with the necessary information for decrypting the object.
        /// </summary>
        /// <param name="request">
        /// AmazonWebServiceRequest  encrypted using the given instruction
        /// </param>
        /// <param name="instructions">
        /// Non-null instruction used to encrypt the data in this AmazonWebServiceRequest .
        /// </param>
        /// <param name="encryptionClient">Encryption client used for put objects</param>
        internal static void UpdateMetadataWithEncryptionInstructionsV2(AmazonWebServiceRequest request, 
            EncryptionInstructions instructions, AmazonS3EncryptionClientBase encryptionClient)
        {
            var keyBytesToStoreInMetadata = instructions.EncryptedEnvelopeKey;
            var base64EncodedEnvelopeKey = Convert.ToBase64String(keyBytesToStoreInMetadata);

            var ivToStoreInMetadata = instructions.InitializationVector;
            var base64EncodedIv = Convert.ToBase64String(ivToStoreInMetadata);

            MetadataCollection metadata = null;

            var putObjectRequest = request as PutObjectRequest;
            if (putObjectRequest != null)
                metadata = putObjectRequest.Metadata;
            
            var initiateMultipartrequest = request as InitiateMultipartUploadRequest;
            if (initiateMultipartrequest != null)
                metadata = initiateMultipartrequest.Metadata;

            if (metadata != null)
            {
                if (encryptionClient.EncryptionMaterials.KMSKeyID != null)
                {
                    metadata.Add(XAmzWrapAlg, XAmzWrapAlgKmsValue);
                }
                else
                {
                    metadata.Add(XAmzWrapAlg, XAmzWrapAlgRsaOaepSha1);
                }
                metadata.Add(XAmzTagLen, DefaultTagLength.ToString());
                metadata.Add(XAmzKeyV2, base64EncodedEnvelopeKey);
                metadata.Add(XAmzCekAlg, encryptionClient.CekAlgorithm);
                metadata.Add(XAmzIV, base64EncodedIv);
                metadata.Add(XAmzMatDesc, JsonMapper.ToJson(instructions.MaterialsDescription));
            }
        }

        /// <summary>
        /// Updates object where the object
        /// input stream contains the decrypted contents.
        /// </summary>
        /// <param name="response">
        /// The getObject response whose contents are to be decrypted.
        /// </param>
        /// <param name="instructions">
        /// The instruction that will be used to encrypt the object data.
        /// </param>
        /// <param name="tagSize">Tag size used for decrypting data using AES GCM algorithm</param>
        internal static void DecryptObjectUsingInstructionsV2(GetObjectResponse response,
            EncryptionInstructions instructions, int tagSize)
        {
            response.ResponseStream = new AesGcmDecryptStream(response.ResponseStream, instructions.EnvelopeKey, instructions.InitializationVector, tagSize);
        }

        /// <summary>
        /// Returns an updated input stream where the input stream contains the encrypted object contents.
        /// The specified instruction will be used to encrypt data.
        /// </summary>
        /// <param name="toBeEncrypted">
        /// The stream whose contents are to be encrypted.
        /// </param>
        /// <param name="instructions">
        /// The instruction that will be used to encrypt the object data.
        /// </param>
        /// <returns>
        /// Encrypted stream, i.e input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptUploadPartRequestUsingInstructionsV2(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            //wrap input stream into AesGcmEncryptStream wrapper
            Stream aesGcmEncryptStream = new AesGcmEncryptStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagLength);
            return aesGcmEncryptStream;
        }

#if AWS_ASYNC_API
        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the KMSKeyID set.
        /// </summary>
        /// <param name="kmsClient">
        /// Used to call KMS to generate a data key.
        /// </param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt data.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsForKMSMaterialsV2Async(ICoreAmazonKMS kmsClient, EncryptionMaterials materials)
        {
            if (materials.KMSKeyID != null)
            {
                var iv = new byte[IVLength];

                // Generate IV, and get both the key and the encrypted key from KMS.
                RandomNumberGenerator.Create().GetBytes(iv);
                var encryptionContext = GenerateEncryptionContext(materials.MaterialsDescription);
                var result = await kmsClient.GenerateDataKeyAsync(materials.KMSKeyID, encryptionContext, KMSKeySpec).ConfigureAwait(false);

                return new EncryptionInstructions(materials.MaterialsDescription, result.KeyPlaintext, result.KeyCiphertext, iv);
            }
            else
                throw new ArgumentException("Error generating encryption instructions.  EncryptionMaterials must have the KMSKeyID set.");
        }
#endif

        private static Dictionary<string, string> GenerateEncryptionContext(Dictionary<string, string> materialsDescription)
        {
            return materialsDescription.Where(pair => !pair.Key.Equals(EncryptionUtils.KMSCmkIDKey))
                .ToDictionary(pair => pair.Key, pair => pair.Value);
        }
    }
}
