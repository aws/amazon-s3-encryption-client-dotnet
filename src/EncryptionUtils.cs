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
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.KeyManagementService.Model;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// The EncryptionUtils class encrypts and decrypts data stored in S3.
    /// It can be used to prepare requests for encryption before they are stored in S3
    /// and to decrypt objects that are retrieved from S3.
    /// </summary>
    internal static partial class EncryptionUtils
    {
        internal const string XAmzPrefix = "x-amz-";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
        
        // v1-specific metadata constants
        internal const string XAmzKey = "x-amz-key";

        // v2-specific metadata constants
        public const string XAmzKeyV2 = "x-amz-key-v2";
        internal const string XAmzWrapAlg = "x-amz-wrap-alg";
        internal const string XAmzCekAlg = "x-amz-cek-alg";
        internal const string XAmzTagLen = "x-amz-tag-len";
        
        // V1-V2 shared meta data constants
        public const string XAmzMatDesc = "x-amz-matdesc";
        private const string XAmzIV = "x-amz-iv";
        private const string XAmzUnencryptedContentLength = "x-amz-unencrypted-content-length";
        private const string XAmzCryptoInstrFile = "x-amz-crypto-instr-file";
        
        // v2-specific constants
        public const string KMSCmkIDKey = "kms_cmk_id";
        public const string KMSKeySpec = "AES_256";
        internal const string XAmzEncryptionContextCekAlg = "aws:x-amz-cek-alg";

        // Old instruction file related constants
        internal const string EncryptionInstructionFileSuffix = "INSTRUCTION_SUFFIX";
        internal const string EncryptedEnvelopeKey = "EncryptedEnvelopeKey";
        internal const string IV = "IV";
        
        internal const int Aes256CtrIv16Length = 16;
        internal const int Aes256GcmIv12Length = 12;
        internal const int DefaultTagBitsLength = 128; // In bits
        internal const int DefaultNonceSize = 12;
        
        internal const string EncryptionInstructionFileV2Suffix = ".instruction";
        internal const string NoSuchKey = "NoSuchKey";
        internal const string SDKEncryptionDocsUrl = "https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html";

        // v2-specific values
        // These values are hard coded here because the
        // .NET client only supports a subset of the features of the Java client.
        internal const string XAmzWrapAlgKmsValue = "kms";
        internal const string XAmzWrapAlgKmsContextValue = "kms+context";
        internal const string XAmzWrapAlgRsaOaepSha1 = "RSA-OAEP-SHA1";
        internal const string XAmzWrapAlgAesGcmValue = "AES/GCM";
        internal const string XAmzAesCbcPaddingCekAlgValue = "AES/CBC/PKCS5Padding";
        internal const string XAmzAesGcmCekAlgValue = "AES/GCM/NoPadding";
        private const string ModeMessage = "Although this mode is supported by other AWS SDKs, the .NET SDK does not support it at this time.";
        internal const string KmsKeyIdNullMessage = "Error generating encryption instructions. EncryptionMaterials must have the KMSKeyID set.";
        internal static readonly HashSet<string> SupportedWrapAlgorithms = new HashSet<string>
        {
            XAmzWrapAlgKmsValue, XAmzWrapAlgKmsContextValue, XAmzWrapAlgRsaOaepSha1, XAmzWrapAlgAesGcmValue
        };
        internal static readonly HashSet<string> SupportedCekAlgorithms = new HashSet<string>
        {
            XAmzAesCbcPaddingCekAlgValue, XAmzAesGcmCekAlgValue
        };
        
        internal static readonly string[] V1V2Keys = { XAmzKey, XAmzKeyV2, XAmzIV, XAmzCekAlg, XAmzTagLen, XAmzMatDesc, XAmzWrapAlg, XAmzUnencryptedContentLength };
        
        private static AlgorithmSuite GetAlgorithmSuitFromCekAlgValue(string cekAlgValue)
        {
            switch (cekAlgValue)
            {
                case XAmzAesCbcPaddingCekAlgValue:
                    return AlgorithmSuite.AlgAes256CbcIv16NoKdf;
                case XAmzAesGcmCekAlgValue:
                    return AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf;
                case XAmzCekAlgAes256GcmHkdfSha512CommitKey:
                    return AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey;
                default:
                    throw new NotSupportedException("Unsupported cek algorithm value: " + cekAlgValue);
            }
        }

        /// <summary>
        /// Decrypts an encrypted Envelope key using the provided encryption materials
        /// and returns it in raw byte array form.
        /// </summary>
        /// <param name="encryptedEnvelopeKey">Encrypted envelope key</param>
        /// <param name="materials">Encryption materials needed to decrypt the encrypted envelope key</param>
        /// <returns></returns>
        internal static byte[] DecryptNonKMSEnvelopeKey(byte[] encryptedEnvelopeKey, EncryptionMaterialsBase materials)
        {
            if (materials.AsymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingAsymmetricKeyPair(materials.AsymmetricProvider, encryptedEnvelopeKey);
            }

            if (materials.SymmetricProvider != null)
            {
                return DecryptEnvelopeKeyUsingSymmetricKey(materials.SymmetricProvider, encryptedEnvelopeKey);
            }

            throw new ArgumentException("Error decrypting non-KMS envelope key. " +
                                        "EncryptionMaterials must have the AsymmetricProvider or SymmetricProvider set.");
        }

        private static byte[] DecryptEnvelopeKeyUsingAsymmetricKeyPair(AsymmetricAlgorithm asymmetricAlgorithm, byte[] encryptedEnvelopeKey)
        {
#if !NETFRAMEWORK
            RSA rsaCrypto = asymmetricAlgorithm as RSA;
            if (rsaCrypto == null)
            {
                throw new NotSupportedException("RSA is the only supported algorithm with AsymmetricProvider.");
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

        internal static string GetEncryptedDataKeyV2OrV3InMetaDataMode(
            MetadataCollection objectMetadata
        )
        {
            if (ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(objectMetadata))
                return objectMetadata[ContentMetaDataV3Utils.EncryptedDataKeyV3];
            return objectMetadata[XAmzKeyV2];
        }
        
        internal static string GetEncryptedDataKeyAlgorithm(
            MetadataCollection objectMetadata
        )
        {
            if (ContentMetaDataV3Utils.IsV3Object(objectMetadata))
                return ContentMetaDataV3Utils.ExpandV3WrapAlgorithm(objectMetadata[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3]);
            return objectMetadata[XAmzWrapAlg];
        }
        
        internal static string GetMaterialDescString(
            MetadataCollection objectMetadata
        )
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#v1-v2-shared
            //= type=exception
            //# This string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
            //= type=exception
            //# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
            
            if (ContentMetaDataV3Utils.IsV3Object(objectMetadata))
                return objectMetadata[ContentMetaDataV3Utils.MatDescV3];
            return objectMetadata[XAmzMatDesc];
        }

        #region StreamDecryption

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
        internal static void DecryptObjectUsingInstructionsGcm(GetObjectResponse response, EncryptionInstructions instructions)
        {
            response.ResponseStream = new AesGcmDecryptStream(response.ResponseStream, instructions.EnvelopeKey, instructions.InitializationVector, DefaultTagBitsLength);
        }

        #endregion

        #region InstructionGeneration
        
        internal static GetObjectRequest GetInstructionFileRequest(GetObjectResponse response, string suffix)
        {
            GetObjectRequest request = new GetObjectRequest
            {
                BucketName = response.BucketName,
                Key = response.Key + suffix
            };
            return request;
        }

        internal static void EnsureSupportedAlgorithms(MetadataCollection metadata, Dictionary<string, string> instructionFilePairs = null)
        {
            if (metadata[XAmzKeyV2] != null)
            {
                var xAmzWrapAlgMetadataValue = metadata[XAmzWrapAlg];
                if (!SupportedWrapAlgorithms.Contains(xAmzWrapAlgMetadataValue))
                {
#pragma warning disable 0618
                    throw new InvalidDataException($"Value '{xAmzWrapAlgMetadataValue}' for metadata key '{XAmzWrapAlg}' is invalid." +
                                                   $"{typeof(AmazonS3EncryptionClientV2).Name} only supports '{XAmzWrapAlgKmsValue}' as the key wrap algorithm. {ModeMessage}");
#pragma warning restore 0618
                }

                var xAmzCekAlgMetadataValue = metadata[XAmzCekAlg];
                if (!(SupportedCekAlgorithms.Contains(xAmzCekAlgMetadataValue)))
#pragma warning disable 0618
                    throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture,
                        "Value '{0}' for metadata key '{1}' is invalid.  {2} only supports '{3}' as the content encryption algorithm. {4}",
                        xAmzCekAlgMetadataValue, XAmzCekAlg, typeof(AmazonS3EncryptionClientV2).Name, XAmzAesCbcPaddingCekAlgValue, ModeMessage));
#pragma warning restore 0618
            }

            if (ContentMetaDataV3Utils.IsV3Object(metadata))
            {
                EnsureSupportedAlgorithmsV3(metadata, instructionFilePairs);
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
            GetObjectResponse response, EncryptionMaterialsBase materials, byte[] decryptedEnvelopeKeyKMS)
        {
            MetadataCollection metadata = response.Metadata;

            var materialDescription = GetMaterialDescriptionFromMetaData(metadata);
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=exception
            //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
            if (ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata))
            {
                return BuildInstructionsForKmsV3(metadata, materials, decryptedEnvelopeKeyKMS, AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey);
            } 
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=exception
            //# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
            if (metadata[XAmzKeyV2] != null) {
                EnsureSupportedAlgorithms(metadata);

                var base64EncodedEncryptedEnvelopeKey = metadata[XAmzKeyV2];
                var encryptedEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedEnvelopeKey);

                var base64EncodedIV = metadata[XAmzIV];
                var IV = Convert.FromBase64String(base64EncodedIV);
                var cekAlgorithm = metadata[XAmzCekAlg];
                var algorithmSuite = GetAlgorithmSuitFromCekAlgValue(cekAlgorithm); 
                var wrapAlgorithm = metadata[XAmzWrapAlg];

                if (decryptedEnvelopeKeyKMS != null)
                {
                    return new EncryptionInstructions(materialDescription, decryptedEnvelopeKeyKMS, encryptedEnvelopeKey, IV, wrapAlgorithm, algorithmSuite);
                }
                else
                {
                    byte[] decryptedEnvelopeKey;
                    if (XAmzWrapAlgRsaOaepSha1.Equals(wrapAlgorithm) || XAmzWrapAlgAesGcmValue.Equals(wrapAlgorithm))
                    {
                        decryptedEnvelopeKey = DecryptNonKmsEnvelopeKeyV2V3(encryptedEnvelopeKey, materials, algorithmSuite);
                    }
                    else
                    {
                        decryptedEnvelopeKey = DecryptNonKMSEnvelopeKey(encryptedEnvelopeKey, materials);
                    }
                    return new EncryptionInstructions(materialDescription, decryptedEnvelopeKey, encryptedEnvelopeKey, IV, wrapAlgorithm, algorithmSuite);
                }
            }
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=exception
            //# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
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
        /// Bundle envelope key with key length and CEK algorithm information
        /// Format: (1 byte is length of the key) + (envelope key) + (UTF-8 encoding of CEK algorithm)
        /// </summary>
        /// <param name="dataKey">Data key to be bundled</param>
        /// <param name="algorithmSuite">Algorithm Suite to be used</param>
        /// <returns></returns>
        private static byte[] EnvelopeKeyForDataKeyV2V3(byte[] dataKey, AlgorithmSuite algorithmSuite)
        {
            var cekAlgorithm = Encoding.UTF8.GetBytes(AlgorithmSuite.GetRepresentativeValue(algorithmSuite));
            int length = 1 + dataKey.Length + cekAlgorithm.Length;
            var envelopeKeyToEncrypt = new byte[length];
            envelopeKeyToEncrypt[0] = (byte)dataKey.Length;
            dataKey.CopyTo(envelopeKeyToEncrypt, 1);
            cekAlgorithm.CopyTo(envelopeKeyToEncrypt, 1 + dataKey.Length);
            return envelopeKeyToEncrypt;
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
                    metadata.Add(XAmzCekAlg, AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite));
                }
                else
                {
                    //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                    //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
                    metadata.Add(XAmzKey, base64EncodedEnvelopeKey);
                }
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
                metadata.Add(XAmzIV, base64EncodedIV);
                
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.
                metadata.Add(XAmzMatDesc, JsonUtils.ToJson(instructions.MaterialsDescription));
            }
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
            if (ContentMetaDataV3Utils.IsV3Object(metadata))
                return metadata[ContentMetaDataV3Utils.EncryptedDataKeyV3] != null && metadata[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3] != null;
            return ((metadata[XAmzKey] != null || metadata[XAmzKeyV2] != null) && metadata[XAmzIV] != null);
        }

#endregion
    }
}
