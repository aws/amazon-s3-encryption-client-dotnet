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
        /// <param name="algorithmSuite">algorithmSuit for decryption</param>
        /// <returns></returns>
        internal static byte[] DecryptNonKmsEnvelopeKeyV2V3(byte[] encryptedEnvelopeKey, EncryptionMaterialsBase materials, AlgorithmSuite algorithmSuite)
        {
            if (materials.AsymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingAsymmetricKeyPairV2V3(materials.AsymmetricProvider, encryptedEnvelopeKey, algorithmSuite);
            }

            if (materials.SymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingSymmetricKeyV2V3(materials.SymmetricProvider, encryptedEnvelopeKey, algorithmSuite);
            }

            throw new ArgumentException("Error decrypting non-KMS envelope key. " +
                                        "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }

        private static byte[] DecryptEnvelopeKeyUsingAsymmetricKeyPairV2V3(AsymmetricAlgorithm asymmetricAlgorithm, byte[] encryptedEnvelopeKey, AlgorithmSuite algorithmSuite)
        {
            var rsa = asymmetricAlgorithm as RSA;
            if (rsa == null)
            {
                throw new NotSupportedException("RSA-OAEP-SHA1 is the only supported algorithm with AsymmetricProvider.");
            }

            var cipher = RsaUtils.CreateRsaOaepSha1Cipher(false, rsa);

            var decryptedEnvelopeKey = cipher.DoFinal(encryptedEnvelopeKey);
            return DecryptedDataKeyFromDecryptedEnvelopeKey(decryptedEnvelopeKey, algorithmSuite);
        }

        private static byte[] DecryptEnvelopeKeyUsingSymmetricKeyV2V3(SymmetricAlgorithm symmetricAlgorithm, byte[] encryptedEnvelopeKey, AlgorithmSuite algorithmSuite)
        {
            var nonce = encryptedEnvelopeKey.Take(DefaultNonceSize).ToArray();
            var encryptedKey = encryptedEnvelopeKey.Skip(nonce.Length).ToArray();
            var associatedText = Encoding.UTF8.GetBytes(AlgorithmSuite.GetRepresentativeValue(algorithmSuite));
            var cipher = AesGcmUtils.CreateCipher(false, symmetricAlgorithm.Key, DefaultTagBitsLength, nonce, associatedText);
            var envelopeKey = cipher.DoFinal(encryptedKey);
            return envelopeKey;
        }

        /// <summary>
        /// Extract and return data key from the decrypted envelope key
        /// Format: (1 byte is length of the key) + (envelope key) + (UTF-8 encoding of CEK algorithm)
        /// </summary>
        /// <param name="decryptedEnvelopeKey">DecryptedEnvelopeKey that contains the data key</param>
        /// <param name="algorithmSuite">AlgorithmSuite used for decryption</param>
        /// <returns></returns>
        /// <exception cref="InvalidDataException">Throws when the CEK algorithm isn't supported for given envelope key</exception>
        private static byte[] DecryptedDataKeyFromDecryptedEnvelopeKey(byte[] decryptedEnvelopeKey, AlgorithmSuite algorithmSuite)
        {
            var keyLength = (int) decryptedEnvelopeKey[0];
            var dataKey = decryptedEnvelopeKey.Skip(1).Take(keyLength);
            var cekAlgorithmFromEnvelopKey = Encoding.UTF8.GetString(decryptedEnvelopeKey.Skip(keyLength + 1).ToArray());
            var representativeValueForAlgorithmSuit = AlgorithmSuite.GetRepresentativeValue(algorithmSuite);
            if (!representativeValueForAlgorithmSuit.Equals(cekAlgorithmFromEnvelopKey))
            {
                throw new InvalidDataException($"Value '{cekAlgorithmFromEnvelopKey}' for CEK algorithm is invalid." +
                                               $"Expected '{representativeValueForAlgorithmSuit}' as the key CEK algorithm.");
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
        /// Encrypted stream, i.e input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptRequestUsingAesGcm(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            if (instructions.AlgorithmSuite.AuthenticationTagLengthInBytes == null)
            {
                throw new AmazonCryptoException(
                    $"Internal error: Got null for {nameof(instructions.AlgorithmSuite.AuthenticationTagLengthInBytes)} for algorithm suite ${instructions.AlgorithmSuite.Id}. " +
                    $"{nameof(instructions.AlgorithmSuite.AuthenticationTagLengthInBytes)} must not be null when encrypting with AES GCM.");
            }
            
            //= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
            //= type=implication
            //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the plaintext data key, the generated IV, and the tag length defined in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
            
            //= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
            //= type=implication
            //# The client MUST NOT provide any AAD when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
            return new AesGcmEncryptCachingStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector, GenericUtils.ConvertByteToBit(instructions.AlgorithmSuite.AuthenticationTagLengthInBytes.Value));
        }

        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the AsymmetricProvider or SymmetricProvider set.
        /// </summary>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt data.
        /// </param>
        /// <param name="algorithmSuite">
        /// The Algorithm suite to be used for encryption and decryption.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForNonKmsMaterialsV2(EncryptionMaterialsV2 materials, AlgorithmSuite algorithmSuite)
        {
            return GenerateInstructionsForNonKmsMaterialsV2(materials.AsymmetricProvider, materials.AsymmetricProviderType,
                materials.SymmetricProvider, materials.SymmetricProviderType, materials.MaterialsDescription, algorithmSuite);
        }
        
        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the AsymmetricProvider or SymmetricProvider set.
        /// </summary>
        /// <param name="asymmetricProvider">Asymmetric provider for key wrapping</param>
        /// <param name="asymmetricAlgorithmType">Type of public key and private key pair based crypto algorithms </param>
        /// <param name="symmetricProvider">Symmetric provider for key wrapping</param>
        /// <param name="symmetricAlgorithmType">Type of single key based crypto algorithms</param>
        /// <param name="materialsDescription">MaterialsDescription of this AsymmetricKeyPair</param>
        /// <param name="algorithmSuite"> The Algorithm suite to be used for encryption and decryption. </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForNonKmsMaterialsV2(AsymmetricAlgorithm asymmetricProvider, 
            AsymmetricAlgorithmType  asymmetricAlgorithmType, SymmetricAlgorithm symmetricProvider, 
            SymmetricAlgorithmType symmetricAlgorithmType, Dictionary<String, String> materialsDescription, AlgorithmSuite algorithmSuite)
        {
            // Generate the IV and key, and encrypt the key locally.
            if (asymmetricProvider != null)
            {
                return EncryptEnvelopeKeyUsingAsymmetricKeyPairV2(asymmetricProvider, asymmetricAlgorithmType, materialsDescription, algorithmSuite);
            }

            if (symmetricProvider != null)
            {
                return EncryptEnvelopeKeyUsingSymmetricKeyV2(symmetricProvider, symmetricAlgorithmType, materialsDescription, algorithmSuite);
            }

            throw new ArgumentException("Error generating encryption instructions. " +
                                        "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }
        
        /// <summary>
        /// Returns encryption instructions to encrypt content with AES/GCM/NoPadding algorithm
        /// Creates encryption key used for AES/GCM/NoPadding and encrypt it with RSA-OAEP-SHA1
        /// </summary>
        /// <param name="asymmetricProvider">Asymmetric provider for key wrapping</param>
        /// <param name="asymmetricAlgorithmType">Type of public key and private key pair based crypto algorithms </param>
        /// <param name="materialsDescription">MaterialsDescription of this AsymmetricKeyPair</param>
        /// <param name="algorithmSuite"> The Algorithm suite to be used for encryption and decryption. </param>
        /// <returns></returns>
        private static EncryptionInstructions EncryptEnvelopeKeyUsingAsymmetricKeyPairV2(AsymmetricAlgorithm asymmetricProvider, 
            AsymmetricAlgorithmType  asymmetricAlgorithmType, Dictionary<String, String> materialsDescription, AlgorithmSuite algorithmSuite)
        {
            var rsa = asymmetricProvider as RSA;
            if (rsa == null)
            {
                throw new NotSupportedException("RSA is the only supported algorithm with this method.");
            }

            switch (asymmetricAlgorithmType)
            {
                case AsymmetricAlgorithmType.RsaOaepSha1:
                {
                    var aesObject = Aes.Create();
                    var nonce = aesObject.IV.Take(DefaultNonceSize).ToArray();
                    var envelopeKeyToEncrypt = EnvelopeKeyForDataKey(aesObject.Key);
                    var cipher = RsaUtils.CreateRsaOaepSha1Cipher(true, rsa);
                    var encryptedEnvelopeKey = cipher.DoFinal(envelopeKeyToEncrypt);

                    var instructions = new EncryptionInstructions(materialsDescription, aesObject.Key, encryptedEnvelopeKey, nonce,
                        XAmzWrapAlgRsaOaepSha1, algorithmSuite);
                    return instructions;
                }
                default:
                {
                    throw new NotSupportedException($"{asymmetricAlgorithmType} isn't supported with AsymmetricProvider");
                }
            }
        }

        /// <summary>
        /// Returns encryption instructions to encrypt content with AES/GCM/NoPadding algorithm
        /// Creates encryption key used for AES/GCM/NoPadding and encrypt it with AES/GCM
        /// Encrypted key follows nonce(12 bytes) + key cipher text(16 or 32 bytes) + tag(16 bytes) format
        /// Tag is appended by the AES/GCM cipher with encryption process
        /// </summary>
        /// <param name="symmetricProvider">Symmetric provider for key wrapping</param>
        /// <param name="symmetricAlgorithmType">Type of single key based crypto algorithms</param>
        /// <param name="materialsDescription">MaterialsDescription of this SymmetricKeyPair</param>
        /// <param name="algorithmSuite"> The Algorithm suite to be used for encryption and decryption. </param>
        /// <returns></returns>
        private static EncryptionInstructions EncryptEnvelopeKeyUsingSymmetricKeyV2(SymmetricAlgorithm symmetricProvider, 
            SymmetricAlgorithmType symmetricAlgorithmType, Dictionary<String, String> materialsDescription, AlgorithmSuite algorithmSuite)
        {
            ThrowIfNotAes256GcmIv12Tag16NoKdf(algorithmSuite);
            var aes = symmetricProvider as Aes;
            if (aes == null)
            {
                throw new NotSupportedException("AES is the only supported algorithm with this method.");
            }

            switch (symmetricAlgorithmType)
            {
                case SymmetricAlgorithmType.AesGcm:
                {
                    var aesObject = Aes.Create();
                    var nonce = aesObject.IV.Take(DefaultNonceSize).ToArray();
                    var associatedText = Encoding.UTF8.GetBytes(XAmzAesGcmCekAlgValue);
                    var cipher = AesGcmUtils.CreateCipher(true, symmetricProvider.Key, DefaultTagBitsLength, nonce, associatedText);
                    var envelopeKey = cipher.DoFinal(aesObject.Key);

                    var encryptedEnvelopeKey = nonce.Concat(envelopeKey).ToArray();

                    var instructions = new EncryptionInstructions(materialsDescription, aesObject.Key, encryptedEnvelopeKey, nonce,
                        XAmzWrapAlgAesGcmValue, algorithmSuite);
                    return instructions;
                }
                default:
                {
                    throw new NotSupportedException($"{symmetricAlgorithmType} isn't supported with SymmetricProvider");
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
        internal static void UpdateMetadataWithEncryptionInstructionsV2(AmazonWebServiceRequest request,
            EncryptionInstructions instructions)
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
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
                metadata.Add(XAmzWrapAlg, instructions.WrapAlgorithm);
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
                metadata.Add(XAmzTagLen, DefaultTagBitsLength.ToString());
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
                metadata.Add(XAmzKeyV2, base64EncodedEnvelopeKey);
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
                metadata.Add(XAmzCekAlg, AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite));
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
                metadata.Add(XAmzIV, base64EncodedIv);
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
                metadata.Add(XAmzMatDesc, JsonUtils.ToJson(instructions.MaterialsDescription));
            }
        }

        internal static PutObjectRequest CreateInstructionFileRequestV2(AmazonWebServiceRequest request, EncryptionInstructions instructions)
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
            var keyBytesToStoreInInstructionFile = instructions.EncryptedEnvelopeKey;
            var base64EncodedEnvelopeKey = Convert.ToBase64String(keyBytesToStoreInInstructionFile);

            var ivToStoreInInstructionFile = instructions.InitializationVector;
            var base64EncodedIv = Convert.ToBase64String(ivToStoreInInstructionFile);
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
            //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
            var keyValuePairs = new Dictionary<string, string>()
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
                {XAmzTagLen,  DefaultTagBitsLength.ToString()},
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
                {XAmzKeyV2,  base64EncodedEnvelopeKey},
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
                {XAmzCekAlg,  AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite)},
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
                {XAmzWrapAlg,  instructions.WrapAlgorithm},
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
                {XAmzIV,  base64EncodedIv},
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
                {XAmzMatDesc,  JsonUtils.ToJson(instructions.MaterialsDescription)},
            };
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=implication
            //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=implication
            //# The serialized JSON string MUST be the only contents of the Instruction File.

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
        /// Encrypted stream, i.e input stream wrapped into encrypted stream
        /// </returns>
        internal static Stream EncryptUploadPartRequestUsingAesGcm(Stream toBeEncrypted, EncryptionInstructions instructions)
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
        /// <param name="algorithmSuitee">
        /// The Algorithm suite to be used for encryption and decryption.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForKMSMaterialsV2(IAmazonKeyManagementService kmsClient, EncryptionMaterialsV2 materials, AlgorithmSuite algorithmSuite)
        {
            return GenerateInstructionsForKMSMaterialsV2(kmsClient, materials.KMSKeyID, materials.KmsType,
                materials.MaterialsDescription, algorithmSuite);
        }
        
        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using kmsKeyId, kmsType and encryptionContextToKMS.
        /// </summary>
        /// <param name="kmsClient">
        /// Used to call KMS to generate a data key.
        /// </param>
        /// <param name="kmsKeyId"> kmsKeyId used to encrypt and decrypt data. </param>
        /// <param name="kmsType"> kmsType enum used in encrypt and decrypt data. </param>
        /// <param name="encryptionContextToKMS"> encryptionContextToKMS used to send encryption context to KMS. </param>
        /// <param name="algorithmSuitee"> algorithmSuite used for encryption and decryption. </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static EncryptionInstructions GenerateInstructionsForKMSMaterialsV2(
            IAmazonKeyManagementService kmsClient, string kmsKeyId, KmsType kmsType, Dictionary<string,string> encryptionContextToKMS, AlgorithmSuite algorithmSuite)
        {
            ThrowIfNotAes256GcmIv12Tag16NoKdf(algorithmSuite);
            if (kmsKeyId == null)
            {
                throw new ArgumentNullException(nameof(kmsKeyId), KmsKeyIdNullMessage);
            }

            switch (kmsType)
            {
                case KmsType.KmsContext:
                {
                    //= ../specification/s3-encryption/encryption.md#content-encryption
                    //= type=implication
                    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
                    var iv = new byte[algorithmSuite.IvLengthInBytes];

                    // Generate iv, and get both the key and the encrypted key from KMS.
                    RandomNumberGenerator.Create().GetBytes(iv);
                    var result = kmsClient.GenerateDataKey(new GenerateDataKeyRequest
                    {
                        KeyId = kmsKeyId,
                        EncryptionContext = encryptionContextToKMS,
                        KeySpec = KMSKeySpec
                    });
                    //= ../specification/s3-encryption/encryption.md#content-encryption
                    //= type=implication
                    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
                    var instructions = new EncryptionInstructions(encryptionContextToKMS, result.Plaintext.ToArray(), result.CiphertextBlob.ToArray(), iv,
                        XAmzWrapAlgKmsContextValue, algorithmSuite);
                    return instructions;
                }
                default:
                    throw new NotSupportedException($"{kmsType} is not supported for KMS Key Id {kmsKeyId}");
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
        /// <param name="algorithmSuite">
        /// The Algorithm suite to be used for encryption and decryption.
        /// </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsForKMSMaterialsV2Async(IAmazonKeyManagementService kmsClient,
            EncryptionMaterialsV2 materials, AlgorithmSuite algorithmSuite)
        {
            return await GenerateInstructionsForKMSMaterialsV2Async(kmsClient, materials.KMSKeyID, materials.KmsType,
                materials.MaterialsDescription, algorithmSuite);
        }
        
        /// <summary>
        /// Generates an instruction that will be used to encrypt an object
        /// using materials with the KMSKeyID set.
        /// </summary>
        /// <param name="kmsClient">
        /// Used to call KMS to generate a data key.
        /// </param>
        /// <param name="kmsKeyId"> kmsKeyId used to encrypt and decrypt data. </param>
        /// <param name="kmsType"> kmsType enum used in encrypt and decrypt data. </param>
        /// <param name="encryptionContextToKMS"> encryptionContextToKMS used to send encryption context to KMS. </param>
        /// <param name="algorithmSuite"> The Algorithm suite to be used for encryption and decryption. </param>
        /// <returns>
        /// The instruction that will be used to encrypt an object.
        /// </returns>
        internal static async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsForKMSMaterialsV2Async(IAmazonKeyManagementService kmsClient,
            string kmsKeyId, KmsType kmsType, Dictionary<string,string> encryptionContextToKMS, AlgorithmSuite algorithmSuite)
        {
            ThrowIfNotAes256GcmIv12Tag16NoKdf(algorithmSuite);
            if (kmsKeyId == null)
            {
                throw new ArgumentNullException(nameof(kmsKeyId), KmsKeyIdNullMessage);
            }

            switch (kmsType)
            {
                case KmsType.KmsContext:
                {
                    //= ../specification/s3-encryption/encryption.md#content-encryption
                    //= type=implication
                    //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
                    var iv = new byte[algorithmSuite.IvLengthInBytes];

                    // Generate iv, and get both the key and the encrypted key from KMS.
                    RandomNumberGenerator.Create().GetBytes(iv);
                    var result = await kmsClient.GenerateDataKeyAsync(new GenerateDataKeyRequest
                    {
                        KeyId = kmsKeyId,
                        EncryptionContext = encryptionContextToKMS,
                        KeySpec = KMSKeySpec
                    }).ConfigureAwait(false);
                    
                    //= ../specification/s3-encryption/encryption.md#content-encryption
                    //= type=implication
                    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
                    var instructions = new EncryptionInstructions(encryptionContextToKMS, result.Plaintext.ToArray(), result.CiphertextBlob.ToArray(), iv,
                        XAmzWrapAlgKmsContextValue, algorithmSuite);
                    return instructions;
                }
                default:
                    throw new NotSupportedException($"{kmsType} is not supported for KMS Key Id {kmsKeyId}");
            }
        }

        /// <summary>
        /// Converts x-amz-matdesc JSON string to dictionary
        /// </summary>
        /// <param name="metadata">Metadata that contains x-amz-matdesc key</param>
        /// <returns></returns>
        internal static Dictionary<string, string> GetMaterialDescriptionFromMetaData(MetadataCollection metadata)
        {
            var materialDescriptionJsonString = GetMaterialDescString(metadata);
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
                context.WrapAlgorithm, context.AlgorithmSuite);
            return instructions;
        }

        /// <summary>
        /// Builds an instruction object from the instruction file.
        /// </summary>
        /// <param name="pairsFromInsFile"> Key value pairs from Instruction file</param>
        /// <param name="materials">
        /// The non-null encryption materials to be used to encrypt and decrypt Envelope key.
        /// </param>
        /// <returns>
        /// A non-null instruction object containing encryption information.
        /// </returns>
        internal static EncryptionInstructions BuildInstructionsUsingInstructionFileV2(Dictionary<string, string> pairsFromInsFile, EncryptionMaterialsBase materials)
        {
            if (pairsFromInsFile.ContainsKey(XAmzKeyV2))
            {
                // The envelope contains data in V2 format
                var encryptedEnvelopeKey = Base64DecodedDataValue(pairsFromInsFile, XAmzKeyV2);

                var initializationVector = Base64DecodedDataValue(pairsFromInsFile, XAmzIV);
                var materialDescription = JsonUtils.ToDictionary((string)pairsFromInsFile[XAmzMatDesc]);

                var cekAlgorithm = StringValue(pairsFromInsFile, XAmzCekAlg);
                var algorithmSuite = GetAlgorithmSuitFromCekAlgValue(cekAlgorithm);
                var decryptedEnvelopeKey = DecryptNonKmsEnvelopeKeyV2V3(encryptedEnvelopeKey, materials, algorithmSuite);
                var wrapAlgorithm = StringValue(pairsFromInsFile, XAmzWrapAlg);

                var instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, null,
                    initializationVector, wrapAlgorithm, algorithmSuite);

                return instructions;
            }
            else if (pairsFromInsFile.ContainsKey(XAmzKey))
            {
                // The envelope contains data in V1 format
                var encryptedEnvelopeKey = Base64DecodedDataValue(pairsFromInsFile, XAmzKey);
                var decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);

                var initializationVector = Base64DecodedDataValue(pairsFromInsFile, XAmzIV);
                var materialDescription = JsonUtils.ToDictionary((string)pairsFromInsFile[XAmzMatDesc]);

                var instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, null, initializationVector);

                return instructions;
            }
            else if (pairsFromInsFile.ContainsKey(EncryptedEnvelopeKey))
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=exception
                //# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
                
                // The envelope contains data in older format
                var encryptedEnvelopeKey = Base64DecodedDataValue(pairsFromInsFile, EncryptedEnvelopeKey);
                var decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);

                var initializationVector = Base64DecodedDataValue(pairsFromInsFile, IV);

                return new EncryptionInstructions(materials.MaterialsDescription, decryptedEnvelopeKey, initializationVector);
            }
            else
            {
                throw new ArgumentException("Missing parameters required for decryption");
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

        private static void ThrowIfNotAes256GcmIv12Tag16NoKdf(AlgorithmSuite algorithmSuite)
        {
            if (algorithmSuite != AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf)
            {
                throw new NotSupportedException($"Internal error: {algorithmSuite} should have been AlgAes256GcmIv12Tag16NoKdf");
            }
        }
        
    }
}
