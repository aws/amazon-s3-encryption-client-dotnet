/*
 * Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
using System.Globalization;
using Amazon.S3.Util;
using Amazon.Runtime.SharedInterfaces;
using Amazon.S3.Internal;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// The EncryptionUtils class encrypts and decrypts data stored in S3.
    /// It can be used to prepare requests for encryption before they are stored in S3
    /// and to decrypt objects that are retrieved from S3.
    /// </summary>
    internal static partial class EncryptionUtils
    {
        // v1-specific constants
        private const string XAmzKey = "x-amz-key";

        // v2-specific constants
        public const string KMSCmkIDKey = "kms_cmk_id";
        public const string KMSKeySpec = "AES_256";
        public const string XAmzKeyV2 = "x-amz-key-v2";
        internal const string XAmzWrapAlg = "x-amz-wrap-alg";
        internal const string XAmzCekAlg = "x-amz-cek-alg";
        internal const string XAmzEncryptionContextCekAlg = "aws:x-amz-cek-alg";
        internal const string XAmzTagLen = "x-amz-tag-len";

        // shared constants
        public const string XAmzMatDesc = "x-amz-matdesc";
        private const string XAmzIV = "x-amz-iv";
        private const string XAmzUnencryptedContentLength = "x-amz-unencrypted-content-length";
        private const string XAmzCryptoInstrFile = "x-amz-crypto-instr-file";
        private const int IVLength = 16;
        internal const int DefaultTagBitsLength = 128; // In bits
        internal const int DefaultNonceSize = 12;
        internal const string EncryptionInstructionFileSuffix = "INSTRUCTION_SUFFIX";
        internal const string EncryptionInstructionFileV2Suffix = ".instruction";

        // v2-specific values
        // These values are hard coded here because the
        // .NET client only supports a subset of the features of the Java client.
        internal const string XAmzWrapAlgKmsValue = "kms";
        internal const string XAmzWrapAlgKmsContextValue = "kms+context";
        internal const string XAmzWrapAlgRsaOaepSha1 = "RSA-OAEP-SHA1";
        internal const string XAmzAesCbcPaddingCekAlgValue = "AES/CBC/PKCS5Padding";
        internal const string XAmzAesGcmCekAlgValue = "AES/GCM/NoPadding";
        private const string ModeMessage = "Although this mode is supported by other AWS SDKs, the .NET SDK does not support it at this time.";
        internal static readonly HashSet<string> SupportedWrapAlgorithms = new HashSet<string>
        {
            XAmzWrapAlgKmsValue, XAmzWrapAlgKmsContextValue, XAmzWrapAlgRsaOaepSha1
        };
        internal static readonly HashSet<string> SupportedCekAlgorithms = new HashSet<string>
        {
            XAmzAesCbcPaddingCekAlgValue, XAmzAesGcmCekAlgValue
        };

        private static byte[] EncryptEnvelopeKeyUsingAsymmetricKeyPair(AsymmetricAlgorithm asymmetricAlgorithm, byte[] envelopeKey)
        {
#if NETSTANDARD
            RSA rsaCrypto = asymmetricAlgorithm as RSA;
            if (rsaCrypto == null)
            {
                throw new NotSupportedException("RSA is the only supported algorithm with this method.");
            }
            return rsaCrypto.Encrypt(envelopeKey, RSAEncryptionPadding.Pkcs1);
#else
            RSACryptoServiceProvider rsaCrypto = asymmetricAlgorithm as RSACryptoServiceProvider;
            return rsaCrypto.Encrypt(envelopeKey, false);
#endif
        }

        private static byte[] EncryptEnvelopeKeyUsingSymmetricKey(SymmetricAlgorithm symmetricAlgorithm, byte[] envelopeKey)
        {
            symmetricAlgorithm.Mode = CipherMode.ECB;
            using (ICryptoTransform encryptor = symmetricAlgorithm.CreateEncryptor())
            {
                return (encryptor.TransformFinalBlock(envelopeKey, 0, envelopeKey.Length));
            }
        }

        /// <summary>
        /// Decrypts an encrypted Envelope key using the provided encryption materials
        /// and returns it in raw byte array form.
        /// </summary>
        /// <param name="encryptedEnvelopeKey">Encrypted envelope key</param>
        /// <param name="materials">Encryption materials needed to decrypt the encrypted envelope key</param>
        /// <returns></returns>
        internal static byte[] DecryptNonKMSEnvelopeKey(byte[] encryptedEnvelopeKey, EncryptionMaterials materials)
        {
            if (materials.AsymmetricProvider != null)
                return DecryptEnvelopeKeyUsingAsymmetricKeyPair(materials.AsymmetricProvider, encryptedEnvelopeKey);
            else if (materials.SymmetricProvider != null)
                return DecryptEnvelopeKeyUsingSymmetricKey(materials.SymmetricProvider, encryptedEnvelopeKey);
            else
                throw new ArgumentException("Error decrypting non-KMS envelope key.  " +
                    "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }

        private static byte[] DecryptEnvelopeKeyUsingAsymmetricKeyPair(AsymmetricAlgorithm asymmetricAlgorithm, byte[] encryptedEnvelopeKey)
        {
#if NETSTANDARD
            RSA rsaCrypto = asymmetricAlgorithm as RSA;
            if (rsaCrypto == null)
            {
                throw new NotSupportedException("RSA is the only supported algorithm with this method.");
            }
            return rsaCrypto.Decrypt(encryptedEnvelopeKey, RSAEncryptionPadding.Pkcs1);
#else
            RSACryptoServiceProvider rsaCrypto = asymmetricAlgorithm as RSACryptoServiceProvider;
            return rsaCrypto.Decrypt(encryptedEnvelopeKey, false);
#endif
        }

        private static byte[] DecryptEnvelopeKeyUsingSymmetricKey(SymmetricAlgorithm symmetricAlgorithm, byte[] encryptedEnvelopeKey)
        {
            symmetricAlgorithm.Mode = CipherMode.ECB;
            using (ICryptoTransform decryptor = symmetricAlgorithm.CreateDecryptor())
            {
                return (decryptor.TransformFinalBlock(encryptedEnvelopeKey, 0, encryptedEnvelopeKey.Length));
            }
        }

        #region StreamEncryption

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
        internal static Stream EncryptRequestUsingInstruction(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            //wrap input stream into AESEncryptionPutObjectStream wrapper
            AESEncryptionPutObjectStream aesEStream;
            aesEStream = new AESEncryptionPutObjectStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector);
            return aesEStream;

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
        internal static Stream EncryptUploadPartRequestUsingInstructions(Stream toBeEncrypted, EncryptionInstructions instructions)
        {
            //wrap input stream into AESEncryptionStreamForUploadPart wrapper
            AESEncryptionUploadPartStream aesEStream;
            aesEStream = new AESEncryptionUploadPartStream(toBeEncrypted, instructions.EnvelopeKey, instructions.InitializationVector);
            return aesEStream;
        }
#endregion

#region StreamDecrption

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
        internal static void DecryptObjectUsingInstructions(GetObjectResponse response, EncryptionInstructions instructions)
        {
            response.ResponseStream = DecryptStream(response.ResponseStream, instructions);
        }

        //wrap encrypted stream into AESDecriptionStream wrapper
        internal static Stream DecryptStream(Stream encryptedStream, EncryptionInstructions encryptionInstructions)
        {
            AESDecryptionStream aesDecryptStream;
            aesDecryptStream = new AESDecryptionStream(encryptedStream, encryptionInstructions.EnvelopeKey, encryptionInstructions.InitializationVector);
            return aesDecryptStream;
        }


        #endregion

        #region InstructionGeneration

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
        internal static EncryptionInstructions GenerateInstructionsForKMSMaterials(ICoreAmazonKMS kmsClient, EncryptionMaterials materials)
        {
            if (materials.KMSKeyID != null)
            {
                var iv = new byte[IVLength];

                // Generate IV, and get both the key and the encrypted key from KMS.
                RandomNumberGenerator.Create().GetBytes(iv);
                var result = kmsClient.GenerateDataKey(materials.KMSKeyID, materials.MaterialsDescription, KMSKeySpec);

                return new EncryptionInstructions(materials.MaterialsDescription, result.KeyPlaintext, result.KeyCiphertext, iv)
                {
                    CekAlgorithm = XAmzAesCbcPaddingCekAlgValue,
                    WrapAlgorithm = XAmzWrapAlgKmsValue
                };
            }
            else
                throw new ArgumentException("Error generating encryption instructions.  EncryptionMaterials must have the KMSKeyID set.");
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
        internal static async System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsForKMSMaterialsAsync(
            ICoreAmazonKMS kmsClient, EncryptionMaterials materials)
        {
            if (materials.KMSKeyID != null)
            {
                var iv = new byte[IVLength];

                // Generate IV, and get both the key and the encrypted key from KMS.
                RandomNumberGenerator.Create().GetBytes(iv);
                var result = await kmsClient.GenerateDataKeyAsync(materials.KMSKeyID, materials.MaterialsDescription, KMSKeySpec).ConfigureAwait(false);

                return new EncryptionInstructions(materials.MaterialsDescription, result.KeyPlaintext, result.KeyCiphertext, iv);
            }
            else
                throw new ArgumentException("Error generating encryption instructions.  EncryptionMaterials must have the KMSKeyID set.");
        }

#endif

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
        internal static EncryptionInstructions GenerateInstructionsForNonKMSMaterials(EncryptionMaterials materials)
        {
            byte[] encryptedEnvelopeKey = null;

            // Generate the IV and key, and encrypt the key locally.
            Aes aesObject = Aes.Create();
            if (materials.AsymmetricProvider != null)
                encryptedEnvelopeKey = EncryptEnvelopeKeyUsingAsymmetricKeyPair(materials.AsymmetricProvider, aesObject.Key);
            else if (materials.SymmetricProvider != null)
                encryptedEnvelopeKey = EncryptEnvelopeKeyUsingSymmetricKey(materials.SymmetricProvider, aesObject.Key);
            else
                throw new ArgumentException("Error generating encryption instructions.  " +
                    "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");

            return new EncryptionInstructions(materials.MaterialsDescription, aesObject.Key, encryptedEnvelopeKey, aesObject.IV)
            {
                CekAlgorithm = XAmzAesCbcPaddingCekAlgValue
            };
        }

        internal static GetObjectRequest GetInstructionFileRequest(GetObjectResponse response)
        {
            GetObjectRequest request = new GetObjectRequest
            {
                BucketName = response.BucketName,
                Key = response.Key + EncryptionInstructionFileSuffix
            };
            return request;
        }

        internal static void EnsureSupportedAlgorithms(MetadataCollection metadata)
        {
            if (metadata[XAmzKeyV2] != null)
            {
                var xAmzWrapAlgMetadataValue = metadata[XAmzWrapAlg];
                if (!SupportedWrapAlgorithms.Contains(xAmzWrapAlgMetadataValue))
                {
                    throw new InvalidDataException($"Value '{xAmzWrapAlgMetadataValue}' for metadata key '{XAmzWrapAlg}' is invalid." +
                                                   $"{typeof(AmazonS3EncryptionClient).Name} only supports '{XAmzWrapAlgKmsValue}' as the key wrap algorithm. {ModeMessage}");
                }

                var xAmzCekAlgMetadataValue = metadata[XAmzCekAlg];
                if (!(SupportedCekAlgorithms.Contains(xAmzCekAlgMetadataValue)))
                    throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture,
                        "Value '{0}' for metadata key '{1}' is invalid.  {2} only supports '{3}' as the content encryption algorithm. {4}",
                        xAmzCekAlgMetadataValue, XAmzCekAlg, typeof(AmazonS3EncryptionClient).Name, XAmzAesCbcPaddingCekAlgValue, ModeMessage));
            }
        }

        /// <summary>
        ///  Builds an instruction object from the object metadata.
        /// </summary>
        /// <param name="response">
        /// A non-null object response that contains encryption information in its metadata.
        /// </param>
        /// <param name="materials">
        /// The non-null encryption materials to be used to encrypt and decrypt Envelope key.
        /// </param>
        /// <param name="decryptedEnvelopeKeyKMS">
        /// The decrypted envelope key to be use if KMS key wrapping is being used.  Or null if non-KMS key wrapping is being used.
        /// </param>
        /// <returns>
        /// </returns>
        internal static EncryptionInstructions BuildInstructionsFromObjectMetadata(
            GetObjectResponse response, EncryptionMaterials materials, byte[] decryptedEnvelopeKeyKMS)
        {
            MetadataCollection metadata = response.Metadata;

            var materialDescription = GetMaterialDescriptionFromMetaData(response.Metadata);

            if (metadata[XAmzKeyV2] != null)
            {
                EnsureSupportedAlgorithms(metadata);

                var base64EncodedEncryptedEnvelopeKey = metadata[XAmzKeyV2];
                var encryptedEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedEnvelopeKey);

                var base64EncodedIV = metadata[XAmzIV];
                var IV = Convert.FromBase64String(base64EncodedIV);
                var tagLength = Convert.ToInt32(metadata[XAmzTagLen]);
                var cekAlgorithm = metadata[XAmzCekAlg];
                var wrapAlgorithm = metadata[XAmzWrapAlg];

                EncryptionInstructions instructions;
                if (decryptedEnvelopeKeyKMS != null)
                {
                    instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKeyKMS, encryptedEnvelopeKey, IV);
                }
                else
                {
                    byte[] decryptedEnvelopeKey;
                    if (XAmzWrapAlgRsaOaepSha1.Equals(wrapAlgorithm))
                    {
                        decryptedEnvelopeKey = DecryptNonKmsEnvelopeKeyV2(encryptedEnvelopeKey, materials);
                    }
                    else
                    {
                        decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);
                    }
                    instructions = new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, encryptedEnvelopeKey, IV);
                }

                instructions.TagLength = tagLength;
                instructions.CekAlgorithm = cekAlgorithm;
                instructions.WrapAlgorithm = wrapAlgorithm;

                return instructions;
            }
            else
            {
                string base64EncodedEncryptedEnvelopeKey = metadata[XAmzKey];
                byte[] encryptedEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedEnvelopeKey);
                byte[] decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);

                string base64EncodedIV = metadata[XAmzIV];
                byte[] IV = Convert.FromBase64String(base64EncodedIV);

                return new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, encryptedEnvelopeKey, IV);
            }
        }

        /// <summary>
        /// Builds an instruction object from the instruction file.
        /// </summary>
        /// <param name="response"> Instruction file GetObject response</param>
        /// <param name="materials">
        /// The non-null encryption materials to be used to encrypt and decrypt Envelope key.
        /// </param>
        /// <param name="decryptNonKmsEnvelopeKey">Func to be used to decrypt non KMS envelope key</param>
        /// <returns>
        /// A non-null instruction object containing encryption information.
        /// </returns>
        internal static EncryptionInstructions BuildInstructionsUsingInstructionFile(GetObjectResponse response, EncryptionMaterials materials,
            Func<byte[], EncryptionMaterials, byte[]> decryptNonKmsEnvelopeKey)
        {
            using (TextReader textReader = new StreamReader(response.ResponseStream))
            {
                JsonData jsonData = JsonMapper.ToObject(textReader);

                var base64EncodedEncryptedEnvelopeKey = jsonData["EncryptedEnvelopeKey"];
                byte[] encryptedEnvelopeKey = Convert.FromBase64String((string)base64EncodedEncryptedEnvelopeKey);
                byte[] decryptedEnvelopeKey = decryptNonKmsEnvelopeKey(encryptedEnvelopeKey, materials);

                var base64EncodedIV = jsonData["IV"];
                byte[] IV = Convert.FromBase64String((string)base64EncodedIV);

                return new EncryptionInstructions(materials.MaterialsDescription, decryptedEnvelopeKey, IV);
            }
        }

        /// <summary>
        /// Build encryption instructions for UploadPartEncryptionContext
        /// </summary>
        /// <param name="context">UploadPartEncryptionContext which contains instructions used for encrypting multipart object</param>
        /// <param name="encryptionMaterials">EncryptionMaterials which contains material used for encrypting multipart object</param>
        /// <returns></returns>
        internal static EncryptionInstructions BuildEncryptionInstructionsForInstructionFile(UploadPartEncryptionContext context, EncryptionMaterials encryptionMaterials)
        {
            var instructions = new EncryptionInstructions(encryptionMaterials.MaterialsDescription, context.EnvelopeKey, context.EncryptedEnvelopeKey, context.FirstIV);
            return instructions;
        }

        #endregion

        #region UpdateMetadata

        /// <summary>
        /// Update the request's ObjectMetadata with the necessary information for decrypting the object.
        /// </summary>
        /// <param name="request">
        /// AmazonWebServiceRequest encrypted using the given instruction
        /// </param>
        /// <param name="instructions">
        /// Non-null instruction used to encrypt the data in this AmazonWebServiceRequest.
        /// </param>
        /// <param name="useV2Metadata">
        /// If true use V2 metadata format, otherwise use V1.
        /// </param>
        internal static void UpdateMetadataWithEncryptionInstructions(AmazonWebServiceRequest request, EncryptionInstructions instructions, bool useV2Metadata)
        {
            byte[] keyBytesToStoreInMetadata = instructions.EncryptedEnvelopeKey;
            string base64EncodedEnvelopeKey = Convert.ToBase64String(keyBytesToStoreInMetadata);

            byte[] IVToStoreInMetadata = instructions.InitializationVector;
            string base64EncodedIV = Convert.ToBase64String(IVToStoreInMetadata);

            MetadataCollection metadata = null;

            var putObjectRequest = request as PutObjectRequest;
            if (putObjectRequest != null)
                metadata = putObjectRequest.Metadata;

            var initiateMultipartrequest = request as InitiateMultipartUploadRequest;
            if (initiateMultipartrequest != null)
                metadata = initiateMultipartrequest.Metadata;

            if (metadata != null)
            {
                if (useV2Metadata)
                {
                    metadata.Add(XAmzKeyV2, base64EncodedEnvelopeKey);
                    metadata.Add(XAmzWrapAlg, instructions.WrapAlgorithm);
                    metadata.Add(XAmzCekAlg, instructions.CekAlgorithm);
                }
                else
                {
                    metadata.Add(XAmzKey, base64EncodedEnvelopeKey);
                }

                metadata.Add(XAmzIV, base64EncodedIV);
                metadata.Add(XAmzMatDesc, JsonMapper.ToJson(instructions.MaterialsDescription));
            }
        }

        internal static PutObjectRequest CreateInstructionFileRequest(AmazonWebServiceRequest request, EncryptionInstructions instructions)
        {
            byte[] keyBytesToStoreInInstructionFile = instructions.EncryptedEnvelopeKey;
            string base64EncodedEnvelopeKey = Convert.ToBase64String(keyBytesToStoreInInstructionFile);

            byte[] IVToStoreInInstructionFile = instructions.InitializationVector;
            string base64EncodedIV = Convert.ToBase64String(IVToStoreInInstructionFile);

            JsonData jsonData = new JsonData();
            jsonData["EncryptedEnvelopeKey"] = base64EncodedEnvelopeKey;
            jsonData["IV"] = base64EncodedIV;

            var contentBody = jsonData.ToJson();

            var putObjectRequest = request as PutObjectRequest;
            if (putObjectRequest != null)
            {
                return GetInstructionFileRequest(putObjectRequest.BucketName, putObjectRequest.Key, EncryptionInstructionFileSuffix, contentBody);
            }

            var completeMultiPartRequest = request as CompleteMultipartUploadRequest;
            if (completeMultiPartRequest != null)
            {
                return GetInstructionFileRequest(completeMultiPartRequest.BucketName, completeMultiPartRequest.Key, EncryptionInstructionFileV2Suffix, contentBody);
            }

            return null;
        }

        /// <summary>
        /// Adds UnEncrypted content length to object metadata
        /// </summary>
        /// <param name="request"></param>
        internal static void AddUnencryptedContentLengthToMetadata(PutObjectRequest request)
        {
            long originalLength = request.InputStream.Length;
            request.Metadata.Add(XAmzUnencryptedContentLength, originalLength.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// checks if encryption credentials are in object metadata
        /// </summary>
        /// <param name="response">Response of the object</param>
        /// <returns></returns>
        internal static bool IsEncryptionInfoInMetadata(GetObjectResponse response)
        {
            MetadataCollection metadata = response.Metadata;
            return ((metadata[XAmzKey] != null || metadata[XAmzKeyV2] != null) && metadata[XAmzIV] != null);
        }

        /// <summary>
        /// checks if encryption credentials are in the instructionfile
        /// </summary>
        /// <param name="response">Instruction file response that contains encryption information</param>
        /// <returns></returns>
        internal static bool IsEncryptionInfoInInstructionFile(GetObjectResponse response)
        {
            MetadataCollection metadata = response.Metadata;

            if (metadata[XAmzCryptoInstrFile] != null)
                return true;
            else
                return false;
        }

#endregion
    }
}
