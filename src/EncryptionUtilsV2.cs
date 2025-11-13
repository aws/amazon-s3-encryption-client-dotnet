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
using System.Text;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption
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
        internal static byte[] DecryptNonKmsEnvelopeKeyV2(byte[] encryptedEnvelopeKey, EncryptionMaterialsBase materials)
        {
            if (materials.AsymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingAsymmetricKeyPairV2(materials.AsymmetricProvider, encryptedEnvelopeKey);
            }

            if (materials.SymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingSymmetricKeyV2(materials.SymmetricProvider, encryptedEnvelopeKey);
            }

            throw new ArgumentException("Error decrypting non-KMS envelope key. " +
                                        "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }

        private static byte[] DecryptEnvelopeKeyUsingAsymmetricKeyPairV2(AsymmetricAlgorithm asymmetricAlgorithm, byte[] encryptedEnvelopeKey)
        {
            var rsa = asymmetricAlgorithm as RSA;
            if (rsa == null)
            {
                throw new NotSupportedException("RSA-OAEP-SHA1 is the only supported algorithm with AsymmetricProvider.");
            }

            var cipher = RsaUtils.CreateRsaOaepSha1Cipher(false, rsa);

            var decryptedEnvelopeKey = cipher.DoFinal(encryptedEnvelopeKey);
            return DecryptedDataKeyFromDecryptedEnvelopeKey(decryptedEnvelopeKey);
        }

        private static byte[] DecryptEnvelopeKeyUsingSymmetricKeyV2(SymmetricAlgorithm symmetricAlgorithm, byte[] encryptedEnvelopeKey)
        {
            var nonce = encryptedEnvelopeKey.Take(DefaultNonceSize).ToArray();
            var encryptedKey = encryptedEnvelopeKey.Skip(nonce.Length).ToArray();
            var associatedText = Encoding.UTF8.GetBytes(XAmzAesGcmCekAlgValue);
            var cipher = AesGcmUtils.CreateCipher(false, symmetricAlgorithm.Key, DefaultTagBitsLength, nonce, associatedText);
            var envelopeKey = cipher.DoFinal(encryptedKey);
            return envelopeKey;
        }

        /// <summary>
        /// Extract and return data key from the decrypted envelope key
        /// Format: (1 byte is length of the key) + (envelope key) + (UTF-8 encoding of CEK algorithm)
        /// </summary>
        /// <param name="decryptedEnvelopeKey">DecryptedEnvelopeKey that contains the data key</param>
        /// <returns></returns>
        /// <exception cref="InvalidDataException">Throws when the CEK algorithm isn't supported for given envelope key</exception>
        private static byte[] DecryptedDataKeyFromDecryptedEnvelopeKey(byte[] decryptedEnvelopeKey)
        {
            var keyLength = (int) decryptedEnvelopeKey[0];
            var dataKey = decryptedEnvelopeKey.Skip(1).Take(keyLength);
            var cekAlgorithm = Encoding.UTF8.GetString(decryptedEnvelopeKey.Skip(keyLength + 1).ToArray());
            if (!XAmzAesGcmCekAlgValue.Equals(cekAlgorithm))
            {
                throw new InvalidDataException($"Value '{cekAlgorithm}' for CEK algorithm is invalid." +
                                               $"{nameof(AmazonS3EncryptionClientV2)} only supports '{XAmzAesGcmCekAlgValue}' as the key CEK algorithm.");
            }

            return dataKey.ToArray();
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
        /// Encrypted stream, i.e. input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptRequestUsingInstructionV2(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            return new AesGcmEncryptCachingStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagBitsLength);
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
        internal static EncryptionInstructions GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterialsV2 materials)
        {
            // Generate the IV and key, and encrypt the key locally.
            if (materials.AsymmetricProvider != null)
            {
                return EncryptEnvelopeKeyUsingAsymmetricKeyPairV2(materials);
            }

            if (materials.SymmetricProvider != null)
            {
                return EncryptEnvelopeKeyUsingSymmetricKeyV2(materials);
            }

            throw new ArgumentException("Error generating encryption instructions. " +
                                        "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }

        private static EncryptionInstructions EncryptEnvelopeKeyUsingAsymmetricKeyPairV2(EncryptionMaterialsV2 materials)
        {
            var rsa = materials.AsymmetricProvider as RSA;
            if (rsa == null)
            {
                throw new NotSupportedException("RSA is the only supported algorithm with this method.");
            }

            switch (materials.AsymmetricProviderType)
            {
                case AsymmetricAlgorithmType.RsaOaepSha1:
                {
                    var aesObject = Aes.Create();
                    var nonce = aesObject.IV.Take(DefaultNonceSize).ToArray();
                    var envelopeKeyToEncrypt = EnvelopeKeyForDataKey(aesObject.Key);
                    var cipher = RsaUtils.CreateRsaOaepSha1Cipher(true, rsa);
                    var encryptedEnvelopeKey = cipher.DoFinal(envelopeKeyToEncrypt);

                    var instructions = new EncryptionInstructions(materials.MaterialsDescription, aesObject.Key, encryptedEnvelopeKey, nonce,
                        XAmzWrapAlgRsaOaepSha1, XAmzAesGcmCekAlgValue);
                    return instructions;
                }
                default:
                {
                    throw new NotSupportedException($"{materials.AsymmetricProviderType} isn't supported with AsymmetricProvider");
                }
            }
        }

        /// <summary>
        /// Returns encryption instructions to encrypt content with AES/GCM/NoPadding algorithm
        /// Creates encryption key used for AES/GCM/NoPadding and encrypt it with AES/GCM
        /// Encrypted key follows nonce(12 bytes) + key cipher text(16 or 32 bytes) + tag(16 bytes) format
        /// Tag is appended by the AES/GCM cipher with encryption process
        /// </summary>
        /// <param name="materials"></param>
        /// <returns></returns>
        private static EncryptionInstructions EncryptEnvelopeKeyUsingSymmetricKeyV2(EncryptionMaterialsV2 materials)
        {
            var aes = materials.SymmetricProvider as Aes;
            if (aes == null)
            {
                throw new NotSupportedException("AES is the only supported algorithm with this method.");
            }

            switch (materials.SymmetricProviderType)
            {
                case SymmetricAlgorithmType.AesGcm:
                {
                    var aesObject = Aes.Create();
                    var nonce = aesObject.IV.Take(DefaultNonceSize).ToArray();
                    var associatedText = Encoding.UTF8.GetBytes(XAmzAesGcmCekAlgValue);
                    var cipher = AesGcmUtils.CreateCipher(true, materials.SymmetricProvider.Key, DefaultTagBitsLength, nonce, associatedText);
                    var envelopeKey = cipher.DoFinal(aesObject.Key);

                    var encryptedEnvelopeKey = nonce.Concat(envelopeKey).ToArray();

                    var instructions = new EncryptionInstructions(materials.MaterialsDescription, aesObject.Key, encryptedEnvelopeKey, nonce,
                        XAmzWrapAlgAesGcmValue, XAmzAesGcmCekAlgValue);
                    return instructions;
                }
                default:
                {
                    throw new NotSupportedException($"{materials.SymmetricProviderType} isn't supported with SymmetricProvider");
                }
            }
        }

        /// <summary>
        /// Bundle envelope key with key length and CEK algorithm information
        /// Format: (1 byte is length of the key) + (envelope key) + (UTF-8 encoding of CEK algorithm)
        /// </summary>
        /// <param name="dataKey">Data key to be bundled</param>
        /// <returns></returns>
        private static byte[] EnvelopeKeyForDataKey(byte[] dataKey)
        {
            var cekAlgorithm = Encoding.UTF8.GetBytes(XAmzAesGcmCekAlgValue);
            int length = 1 + dataKey.Length + cekAlgorithm.Length;
            var envelopeKeyToEncrypt = new byte[length];
            envelopeKeyToEncrypt[0] = (byte)dataKey.Length;
            dataKey.CopyTo(envelopeKeyToEncrypt, 1);
            cekAlgorithm.CopyTo(envelopeKeyToEncrypt, 1 + dataKey.Length);
            return envelopeKeyToEncrypt;
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
                metadata.Add(XAmzWrapAlg, instructions.WrapAlgorithm);
                metadata.Add(XAmzTagLen, DefaultTagBitsLength.ToString());
                metadata.Add(XAmzKeyV2, base64EncodedEnvelopeKey);
                metadata.Add(XAmzCekAlg, instructions.CekAlgorithm);
                metadata.Add(XAmzIV, base64EncodedIv);
                metadata.Add(XAmzMatDesc, JsonUtils.ToJson(instructions.MaterialsDescription));
            }
        }

        internal static PutObjectRequest CreateInstructionFileRequestV2(AmazonWebServiceRequest request, EncryptionInstructions instructions)
        {
            var keyBytesToStoreInInstructionFile = instructions.EncryptedEnvelopeKey;
            var base64EncodedEnvelopeKey = Convert.ToBase64String(keyBytesToStoreInInstructionFile);

            var ivToStoreInInstructionFile = instructions.InitializationVector;
            var base64EncodedIv = Convert.ToBase64String(ivToStoreInInstructionFile);

            var keyValuePairs = new Dictionary<string, string>()
            {
                {XAmzTagLen,  DefaultTagBitsLength.ToString()},
                {XAmzKeyV2,  base64EncodedEnvelopeKey},
                {XAmzCekAlg,  instructions.CekAlgorithm},
                {XAmzWrapAlg,  instructions.WrapAlgorithm},
                {XAmzIV,  base64EncodedIv},
                {XAmzMatDesc,  JsonUtils.ToJson(instructions.MaterialsDescription)},
            };

            var contentBody = JsonUtils.ToJson(keyValuePairs);

            var putObjectRequest = request as PutObjectRequest;
            if (putObjectRequest != null)
            {
                return GetInstructionFileRequest(putObjectRequest.BucketName, putObjectRequest.Key, EncryptionInstructionFileV2Suffix, contentBody);
            }

            var completeMultiPartRequest = request as CompleteMultipartUploadRequest;
            if (completeMultiPartRequest != null)
            {
                return GetInstructionFileRequest(completeMultiPartRequest.BucketName, completeMultiPartRequest.Key, EncryptionInstructionFileV2Suffix, contentBody);
            }

            return null;
        }

        private static PutObjectRequest GetInstructionFileRequest(string bucketName, string key, string suffix, string contentBody)
        {
            var instructionFileRequest = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"{key}{suffix}",
                ContentBody = contentBody
            };
            instructionFileRequest.Metadata.Add(XAmzCryptoInstrFile, "");
            return instructionFileRequest;
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
        /// Encrypted stream, i.e. input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptUploadPartRequestUsingInstructionsV2(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            //wrap input stream into AesGcmEncryptCachingStream wrapper
            Stream aesGcmEncryptStream = new AesGcmEncryptCachingStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagBitsLength);
            return aesGcmEncryptStream;
        }

#if NETFRAMEWORK
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
        /// <param name="encryptionContext">
        /// The encryption context to be used in KMS Generate Data Key API call.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForKMSMaterialsV2(IAmazonKeyManagementService kmsClient, EncryptionMaterialsV2 materials, Dictionary<string, string> encryptionContext)
        {
            if (materials.KMSKeyID == null)
            {
                throw new ArgumentNullException(nameof(materials.KMSKeyID), KmsKeyIdNullMessage);
            }

            switch (materials.KmsType)
            {
                case KmsType.KmsContext:
                {
                    var nonce = new byte[DefaultNonceSize];

                    // Generate nonce, and get both the key and the encrypted key from KMS.
                    RandomNumberGenerator.Create().GetBytes(nonce);
                    var result = kmsClient.GenerateDataKey(new GenerateDataKeyRequest
                    {
                        KeyId = materials.KMSKeyID,
                        EncryptionContext = encryptionContext,
                        KeySpec = KMSKeySpec
                    });

                    var instructions = new EncryptionInstructions(encryptionContext, result.Plaintext.ToArray(), result.CiphertextBlob.ToArray(), nonce,
                        XAmzWrapAlgKmsContextValue, XAmzAesGcmCekAlgValue);
                    return instructions;
                }
                default:
                    throw new NotSupportedException($"{materials.KmsType} is not supported for KMS Key Id {materials.KMSKeyID}");
            }
        }
#endif
        
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
        /// <param name="encryptionContext">
        /// The encryption context to be used in KMS Generate Data Key API call.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsForKMSMaterialsV2Async(IAmazonKeyManagementService kmsClient,
            EncryptionMaterialsV2 materials, Dictionary<string, string> encryptionContext)
        {
            if (materials.KMSKeyID == null)
            {
                throw new ArgumentNullException(nameof(materials.KMSKeyID), KmsKeyIdNullMessage);
            }

            switch (materials.KmsType)
            {
                case KmsType.KmsContext:
                {
                    var nonce = new byte[DefaultNonceSize];

                    // Generate nonce, and get both the key and the encrypted key from KMS.
                    RandomNumberGenerator.Create().GetBytes(nonce);
                    var result = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
                    {
                        KeyId = materials.KMSKeyID,
                        EncryptionContext = encryptionContext,
                        KeySpec = KMSKeySpec
                    }).ConfigureAwait(false);

                    var instructions = new EncryptionInstructions(encryptionContext, result.Plaintext.ToArray(), result.CiphertextBlob.ToArray(), nonce,
                        XAmzWrapAlgKmsContextValue, XAmzAesGcmCekAlgValue);
                    return instructions;
                }
                default:
                    throw new NotSupportedException($"{materials.KmsType} is not supported for KMS Key Id {materials.KMSKeyID}");
            }
        }

        /// <summary>
        /// Converts x-amz-matdesc JSON string to dictionary
        /// </summary>
        /// <param name="metadata">Metadata that contains x-amz-matdesc key</param>
        /// <returns></returns>
        internal static Dictionary<string, string> GetMaterialDescriptionFromMetaData(MetadataCollection metadata)
        {
            var materialDescriptionJsonString = metadata[XAmzMatDesc];
            if (materialDescriptionJsonString == null)
            {
                return new Dictionary<string, string>();
            }

            var materialDescription = JsonUtils.ToDictionary(materialDescriptionJsonString);
            return materialDescription;
        }

        internal static GetObjectRequest GetInstructionFileRequestV2(GetObjectResponse response)
        {
            var request = new GetObjectRequest
            {
                BucketName = response.BucketName,
                Key = response.Key + EncryptionInstructionFileV2Suffix
            };
            return request;
        }

        /// <summary>
        /// Build encryption instructions for UploadPartEncryptionContext
        /// </summary>
        /// <param name="context">UploadPartEncryptionContext which contains instructions used for encrypting multipart object</param>
        /// <param name="encryptionMaterials">EncryptionMaterials which contains material used for encrypting multipart object</param>
        /// <returns></returns>
        internal static EncryptionInstructions BuildEncryptionInstructionsForInstructionFileV2(UploadPartEncryptionContext context, EncryptionMaterialsBase encryptionMaterials)
        {
            var instructions = new EncryptionInstructions(encryptionMaterials.MaterialsDescription, context.EnvelopeKey, context.EncryptedEnvelopeKey, context.FirstIV,
                context.WrapAlgorithm, context.CekAlgorithm);
            return instructions;
        }

        /// <summary>
        /// Builds an instruction object from the instruction file.
        /// </summary>
        /// <param name="response"> Instruction file GetObject response</param>
        /// <param name="materials">
        /// The non-null encryption materials to be used to encrypt and decrypt Envelope key.
        /// </param>
        /// <returns>
        /// A non-null instruction object containing encryption information.
        /// </returns>
        internal static EncryptionInstructions BuildInstructionsUsingInstructionFileV2(GetObjectResponse response, EncryptionMaterialsBase materials)
        {
            using (TextReader textReader = new StreamReader(response.ResponseStream))
            {
                var keyValuePair = JsonUtils.ToDictionary(textReader.ReadToEnd());

                if (keyValuePair.ContainsKey(XAmzKeyV2))
                {
                    // The envelope contains data in V2 format
                    var encryptedEnvelopeKey = Base64DecodedDataValue(keyValuePair, XAmzKeyV2);
                    var decryptedEnvelopeKey = DecryptNonKmsEnvelopeKeyV2(encryptedEnvelopeKey, materials);

                    var initializationVector = Base64DecodedDataValue(keyValuePair, XAmzIV);
                    var materialDescription = JsonUtils.ToDictionary((string)keyValuePair[XAmzMatDesc]);

                    var cekAlgorithm = StringValue(keyValuePair, XAmzCekAlg);
                    var wrapAlgorithm = StringValue(keyValuePair, XAmzWrapAlg);

                    var instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, null,
                        initializationVector, wrapAlgorithm, cekAlgorithm);

                    return instructions;
                }
                else if (keyValuePair.ContainsKey(XAmzKey))
                {
                    // The envelope contains data in V1 format
                    var encryptedEnvelopeKey = Base64DecodedDataValue(keyValuePair, XAmzKey);
                    var decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);

                    var initializationVector = Base64DecodedDataValue(keyValuePair, XAmzIV);
                    var materialDescription = JsonUtils.ToDictionary((string)keyValuePair[XAmzMatDesc]);

                    var instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, null, initializationVector);

                    return instructions;
                }
                else if (keyValuePair.ContainsKey(EncryptedEnvelopeKey))
                {
                    // The envelope contains data in older format
                    var encryptedEnvelopeKey = Base64DecodedDataValue(keyValuePair, EncryptedEnvelopeKey);
                    var decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);

                    var initializationVector = Base64DecodedDataValue(keyValuePair, IV);

                    return new EncryptionInstructions(materials.MaterialsDescription, decryptedEnvelopeKey, initializationVector);
                }
                else
                {
                    throw new ArgumentException("Missing parameters required for decryption");
                }
            }
        }

        private static byte[] Base64DecodedDataValue(Dictionary<string, string> keyValuePairs, string key)
        {
            if (!keyValuePairs.TryGetValue(key, out var base64EncodedValue))
            {
                throw new ArgumentNullException(nameof(key));
            }

            return Convert.FromBase64String((string)base64EncodedValue);
        }

        private static string StringValue(Dictionary<string, string> keyValuePairs, string key)
        {
            if (!keyValuePairs.TryGetValue(key, out var stringValue))
            {
                throw new ArgumentNullException(nameof(key));
            }

            return stringValue;
        }
    }
}
