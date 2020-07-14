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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Amazon.Runtime;
using Amazon.Runtime.Internal.Util;
using Amazon.Runtime.SharedInterfaces;
using Amazon.S3.Model;
using ThirdParty.Json.LitJson;

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
            if (rsaCryptoServiceProvider == null)
            {
                throw new NotSupportedException("RSA-OAEP-SHA1 is the only supported algorithm with this method.");
            }

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
            if (rsaCryptoServiceProvider == null)
            {
                throw new NotSupportedException("RSA-OAEP-SHA1 is the only supported algorithm with this method.");
            }

            var aesObject = Aes.Create();
            var encryptedEnvelopeKey = rsaCryptoServiceProvider.Encrypt(aesObject.Key, true);
            var nonce = aesObject.IV.Take(DefaultNonceSize).ToArray();
            var instructions = new EncryptionInstructions(materials.MaterialsDescription, aesObject.Key, encryptedEnvelopeKey, nonce);
            GenerateAesGcmInstrucations(instructions);
            return instructions;
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
            //wrap input stream into AesGcmEncryptCachingStream wrapper
            Stream aesGcmEncryptStream = new AesGcmEncryptCachingStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagLength);
            return aesGcmEncryptStream;
        }

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
        internal static EncryptionInstructions GenerateInstructionsForKMSMaterialsV2(ICoreAmazonKMS kmsClient, EncryptionMaterials materials)
        {
            if (materials.KMSKeyID != null)
            {
                var nonce = new byte[DefaultNonceSize];

                // Generate nonce, and get both the key and the encrypted key from KMS.
                RandomNumberGenerator.Create().GetBytes(nonce);
                var encryptionContext = GenerateEncryptionContextForKMS(materials.MaterialsDescription);
                encryptionContext[XAmzEncryptionContextCekAlg] = XAmzAesGcmCekAlgValue;
                var result = kmsClient.GenerateDataKey(materials.KMSKeyID, encryptionContext, KMSKeySpec);

                var instructions = new EncryptionInstructions(materials.MaterialsDescription, result.KeyPlaintext, result.KeyCiphertext, nonce);
                GenerateAesGcmInstrucations(instructions);
                instructions.MaterialsDescription[XAmzEncryptionContextCekAlg] = XAmzAesGcmCekAlgValue;
                return instructions;
            }

            throw new ArgumentException("Error generating encryption instructions.  EncryptionMaterials must have the KMSKeyID set.");
        }

        private static void GenerateAesGcmInstrucations(EncryptionInstructions instructions)
        {
            // Set AES GCM specific data
            instructions.MaterialsDescription[XAmzCekAlg] = XAmzAesGcmCekAlgValue;
            instructions.MaterialsDescription[XAmzTagLen] = DefaultTagLength.ToString();
            instructions.MaterialsDescription[XAmzWrapAlg] = XAmzWrapAlgRsaOaepSha1;
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
                var nonce = new byte[DefaultNonceSize];

                // Generate nonce, and get both the key and the encrypted key from KMS.
                RandomNumberGenerator.Create().GetBytes(nonce);
                var encryptionContext = GenerateEncryptionContextForKMS(materials.MaterialsDescription);
                encryptionContext[XAmzEncryptionContextCekAlg] = XAmzAesGcmCekAlgValue;
                var result = await kmsClient.GenerateDataKeyAsync(materials.KMSKeyID, encryptionContext, KMSKeySpec).ConfigureAwait(false);

                var instructions = new EncryptionInstructions(materials.MaterialsDescription, result.KeyPlaintext, result.KeyCiphertext, nonce);
                GenerateAesGcmInstrucations(instructions);
                instructions.MaterialsDescription[XAmzEncryptionContextCekAlg] = XAmzAesGcmCekAlgValue;
                return instructions;
            }

            throw new ArgumentException("Error generating encryption instructions.  EncryptionMaterials must have the KMSKeyID set.");
        }
#endif

        private static Dictionary<string, string> GenerateEncryptionContextForKMS(Dictionary<string, string> materialsDescription)
        {
            return materialsDescription.Where(pair => pair.Key.Equals(XAmzEncryptionContextCekAlg))
                .ToDictionary(pair => pair.Key, pair => pair.Value);
        }

        /// <summary>
        /// Build encryption instructions for UploadPartEncryptionContext
        /// </summary>
        /// <param name="context">UploadPartEncryptionContext which contains instructions used for encrypting multipart object</param>
        /// <param name="encryptionMaterials">EncryptionMaterials which contains material used for encrypting multipart object</param>
        /// <returns></returns>
        internal static EncryptionInstructions BuildEncryptionInstructionsForInstructionFileV2(UploadPartEncryptionContext context, EncryptionMaterials encryptionMaterials)
        {
            var instructions = new EncryptionInstructions(encryptionMaterials.MaterialsDescription, context.EnvelopeKey, context.EncryptedEnvelopeKey, context.FirstIV);

            instructions.MaterialsDescription[XAmzCekAlg] = XAmzAesGcmCekAlgValue;
            instructions.MaterialsDescription[XAmzTagLen] = DefaultTagLength.ToString();
            instructions.MaterialsDescription[XAmzWrapAlg] = XAmzWrapAlgRsaOaepSha1;

            return instructions;
        }
    }
}
