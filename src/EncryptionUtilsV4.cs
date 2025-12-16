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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.KeyManagementService.Model;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// V3 format support for the EncryptionUtils class
    /// </summary>
    internal static partial class EncryptionUtils
    {
        // v3 content algorithm suite
        internal const string XAmzCekAlgAes256GcmHkdfSha512CommitKey = "115"; // 0x0073
        internal static readonly byte[] Aes256GcmHkdfSha512AlgorithmSuiteIdBytes = { 0x00, 0x73 };
        
        internal static readonly byte[] CommitKeyBytes = Encoding.UTF8.GetBytes("COMMITKEY");
        internal static readonly byte[] DeriveKeyBytes = Encoding.UTF8.GetBytes("DERIVEKEY");
        
        // Only "kms+context", "RSA-OAEP-SHA1" and "AES/GCM" are supported in V3 object
        internal static readonly HashSet<string> SupportedWrapAlgorithmsV3 = new HashSet<string>
        {
            XAmzWrapAlgKmsContextValue, XAmzWrapAlgRsaOaepSha1, XAmzWrapAlgAesGcmValue
        };
        
        internal static bool IsKmsWrappingAlgV3(string wrapAlgorithm)
        {
            if (XAmzWrapAlgKmsContextValue.Equals(wrapAlgorithm))
                return true;
            if (XAmzWrapAlgAesGcmValue.Equals(wrapAlgorithm) || XAmzWrapAlgRsaOaepSha1.Equals(wrapAlgorithm))
                return false;
            throw new UnsupportedOperationException($"wrapAlgorithm {wrapAlgorithm} is not supported. " +
                                                    "The only supported wrap algorithm for V3 object format are " +
                                                    $"{XAmzWrapAlgKmsContextValue}, {XAmzWrapAlgAesGcmValue} and {XAmzWrapAlgRsaOaepSha1}");
        }

        internal static void EnsureSupportedAlgorithmsV3(MetadataCollection metadata, Dictionary<string, string> instructionFilePairs = null)
        {
            if (!ContentMetaDataV3Utils.IsV3Object(metadata))
            {
                throw new InvalidOperationException($"Invalid method {nameof(EnsureSupportedAlgorithmsV3)} is getting called for non V3 object." +
                                                    "This should not be happening.");
            }
            if (!ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata) && instructionFilePairs == null)
            {
                return;
            }
            var encryptedDataKeyAlgorithm = instructionFilePairs == null
                ? metadata[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3]
                : instructionFilePairs[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3];
            var xAmzWrapAlgValue= ContentMetaDataV3Utils.ExpandV3WrapAlgorithm(encryptedDataKeyAlgorithm);
            
            if (!SupportedWrapAlgorithmsV3.Contains(xAmzWrapAlgValue))
            {
                throw new InvalidDataException($"Value '{xAmzWrapAlgValue}' for metadata key '{ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3}' is invalid." +
                                               $"AmazonS3EncryptionClient only supports '{XAmzWrapAlgKmsContextValue}' as the key wrap algorithm.");
            }

            var xAmzCekAlgMetadataValue = metadata[ContentMetaDataV3Utils.ContentCipherV3];
            if (!XAmzCekAlgAes256GcmHkdfSha512CommitKey.Equals(xAmzCekAlgMetadataValue))
                throw new InvalidDataException(
                    $"Value '{xAmzCekAlgMetadataValue}' for metadata key '{ContentMetaDataV3Utils.ContentCipherV3}' is invalid." +
                    $"The only supported one is '{XAmzCekAlgAes256GcmHkdfSha512CommitKey}'");
        }
        
        internal static EncryptionInstructions BuildEncInstructionsForV3Object(byte[] encryptedEnvelopeKey, byte[] messageId, 
            string wrapAlgorithm, Dictionary<string, string> encryptionContext, Dictionary<string, string> materialDescription, 
            EncryptionMaterialsBase materials, byte[] decryptedEnvelopeKeyKms, byte[] keyCommitment, AlgorithmSuite algorithmSuite)
        {
            if (decryptedEnvelopeKeyKms != null)
            {
                //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
                if (decryptedEnvelopeKeyKms.Length != GenericUtils.ConvertBitToByte(algorithmSuite.KeyDerivationInputLengthInBits))
                {
                    throw new AmazonCryptoException($"The length of decrypted KMS envelope key is {decryptedEnvelopeKeyKms.Length} bytes " +
                                                    $"but the algorithm suite requires {GenericUtils.ConvertBitToByte(algorithmSuite.KeyDerivationInputLengthInBits)} bytes.");
                } 
                return new EncryptionInstructions(materialDescription, encryptionContext, decryptedEnvelopeKeyKms, encryptedEnvelopeKey, 
                    wrapAlgorithm, messageId, keyCommitment, algorithmSuite);
            }
            var decryptedEnvelopeKey = DecryptNonKmsEnvelopeKeyV2V3(encryptedEnvelopeKey, materials, algorithmSuite);
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //# - The length of the input keying material MUST equal the key derivation input length specified by the algorithm suite commit key derivation setting.
            if (decryptedEnvelopeKey.Length != GenericUtils.ConvertBitToByte(algorithmSuite.KeyDerivationInputLengthInBits))
            {
                throw new AmazonCryptoException($"The length of decrypted envelope key is {decryptedEnvelopeKey.Length} bytes " +
                                                $"but the algorithm suite requires {GenericUtils.ConvertBitToByte(algorithmSuite.KeyDerivationInputLengthInBits)} bytes.");
            } 
            return new EncryptionInstructions(materialDescription, encryptionContext, decryptedEnvelopeKey, encryptedEnvelopeKey, 
                wrapAlgorithm, messageId, keyCommitment, algorithmSuite);
        }
        
        internal static void ValidateMessageId(byte[] messageId, AlgorithmSuite algorithmSuite)
        {
            if (messageId.Length != GenericUtils.ConvertBitToByte(algorithmSuite.SaltLengthInBits))
                throw new InvalidDataException($"Invalid message id length: {messageId.Length}." +
                                               $"Expected length is {algorithmSuite.SaltLengthInBits} bits.");
        }

        internal static byte[] GetInfoForHkdf(AlgorithmSuite algSuite)
        {
            switch (algSuite.Id)
            {
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey:
                    //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                    //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string DERIVEKEY as UTF8 encoded bytes.
                    return algSuite.AlgorithmSuiteIdBytes.Concat(DeriveKeyBytes).ToArray();
                default:
                    throw new ArgumentException($"Algorithm suite {algSuite.Id} does not require HKDF or is not supported.");
            }
        }
        
        internal static byte[] GetInfoForCommitKey(AlgorithmSuite algSuite)
        {
            switch (algSuite.Id)
            {
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey:
                    //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                    //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
                    return algSuite.AlgorithmSuiteIdBytes.Concat(CommitKeyBytes).ToArray();
                default:
                    throw new ArgumentException($"Algorithm suite {algSuite.Id} does not require key commitment or is not supported.");
            }
        }

        private static byte[] DeriveHkdf(EncryptionInstructions instructions)
        {
            switch (instructions.AlgorithmSuite.Id)
            {
                //= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
                //= type=implication
                //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey:
                    //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                    //# - The hash function MUST be specified by the algorithm suite commitment settings.
                    if (instructions.AlgorithmSuite.KdfHashFunction != KdfHashFunction.SHA512)
                    {
                        throw new ArgumentException(
                            $"Internal Error: KdfHashFunction is {instructions.AlgorithmSuite.KdfHashFunction} is not supported. " +
                            $"Only {nameof(KdfHashFunction.SHA512)} is supported.");
                    }

                    if (instructions.MessageId.Length !=
                        GenericUtils.ConvertBitToByte(AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey.SaltLengthInBits))
                    {
                        //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                        //= type=implication
                        //# - The salt MUST be the Message ID with the length defined in the algorithm suite.
                        throw new ArgumentException(
                            $"Internal Error: MessageId length is not equal to {AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey.SaltLengthInBits} bits." +
                            $" MessageId is input to salt whose length must be equal to the one defined in algorithm suite.");
                    }
                    var info = GetInfoForHkdf(instructions.AlgorithmSuite);
                    return HkdfSha512.ForAes(
                        //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                        //= type=implication
                        //# - The input keying material MUST be the plaintext data key (PDK) generated by the key provider.
                        instructions.EnvelopeKey,
                        instructions.MessageId, 
                        info,
                        //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                        //= type=implication
                        //# - The length of the output keying material MUST equal the encryption key length specified by the algorithm suite encryption settings.
                        GenericUtils.ConvertBitToByte(instructions.AlgorithmSuite.EncryptionKeyLengthInBits)
                        );
                default:
                    throw new ArgumentException($"cekAlgorithm: {instructions.AlgorithmSuite} does not require HKDF.");
            }
        }
        
        internal static byte[] DeriveKeyCommitment(EncryptionInstructions instructions)
        {
            switch (instructions.AlgorithmSuite.Id)
            {
                //= ../specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
                //= type=implication
                //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key as described in [Key Derivation](key-derivation.md).
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey:
                    if (instructions.AlgorithmSuite.KeyDerivationOutputLengthInBits == null)
                    {
                        throw new ArgumentException(
                            $"Internal error: KeyDerivationOutputLengthInBits is null in {nameof(AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey)}");
                    }
                    var info = GetInfoForCommitKey(instructions.AlgorithmSuite);
                    return HkdfSha512.ForCommitment(
                        instructions.EnvelopeKey, 
                        instructions.MessageId,
                        info,
                        //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                        //= type=implication
                        //# - The length of the output keying material MUST equal the commit key length specified by the supported algorithm suites.
                        GenericUtils.ConvertBitToByte(instructions.AlgorithmSuite.KeyDerivationOutputLengthInBits.Value)
                        );
                default:
                    throw new ArgumentException($"cekAlgorithm: {instructions.AlgorithmSuite} does not require key commitment.");
            }
        }

        internal static void DecryptObjectUsingV3Instructions(GetObjectResponse response, EncryptionInstructions instructions)
        {
            ValidateMessageId(instructions.MessageId, instructions.AlgorithmSuite);
            
            var derivedKeyCommitment = DeriveKeyCommitment(instructions);
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=implication
            //# When using an algorithm suite which supports key commitment, the verification of the derived key commitment value MUST be done in constant time.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=implication
            //# When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match before deriving the [derived encryption key](./key-derivation.md#hkdf-operation).
            if (!S3ecImplementedCryptographicOperations.FixedTimeEquals(derivedKeyCommitment, instructions.KeyCommitment))
                //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
                //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
                throw new AmazonCryptoException("Stored key commitment does not match the derived key commitment value");
            
            var derivedKey = DeriveHkdf(instructions);
            
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            //# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
            var allOneIv = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
            
            //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the derived encryption key, an IV containing only zeros, and the tag length defined in the Algorithm Suite when encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.
            
            response.ResponseStream = new AesGcmDecryptStream(
                response.ResponseStream, 
                derivedKey, 
                allOneIv, 
                DefaultTagBitsLength,
                //= ../specification/s3-encryption/key-derivation.md#hkdf-operation
                //= type=implication
                //# The client MUST set the AAD to the Algorithm Suite ID represented as bytes.
                instructions.AlgorithmSuite.AlgorithmSuiteIdBytes);
        }

        internal static EncryptionInstructions BuildInstructionsForKmsV3(MetadataCollection metadata,
            EncryptionMaterialsBase materials, byte[] decryptedEnvelopeKeyKMS, AlgorithmSuite algorithmSuite)
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //= type=exception
            //# The S3EC SHOULD support decoding the S3 Server's "double encoding".
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
            EnsureSupportedAlgorithmsV3(metadata);
            var base64EncodedEncryptedEnvelopeKey = metadata[ContentMetaDataV3Utils.EncryptedDataKeyV3];
            var encryptedEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedEnvelopeKey);
            var base64EncodedMessageId = metadata[ContentMetaDataV3Utils.MessageIdV3];
            var messageId = Convert.FromBase64String(base64EncodedMessageId);
            var wrapAlgorithm = ContentMetaDataV3Utils.ExpandV3WrapAlgorithm(metadata[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3]);
            var encryptionContext = GetEncryptionContextFromMetaData(metadata);
            var base64KeyCommitment = metadata[ContentMetaDataV3Utils.KeyCommitmentV3];
            var keyCommitment = Convert.FromBase64String(base64KeyCommitment);
            // Decryption of envelop key (if non KMS) happens inside BuildEncInstructionsForV3Object
            return BuildEncInstructionsForV3Object(encryptedEnvelopeKey, messageId, wrapAlgorithm, encryptionContext, null, materials, 
                decryptedEnvelopeKeyKMS, keyCommitment, algorithmSuite);
        }

        /// <summary>
        /// Builds an instruction object from the instruction file for S3EC V3 object only
        /// </summary>
        /// <param name="objectMetaData"> The metadata of object from S3</param> 
        /// <param name="pairsFromInsFile"> Key value pairs from Instruction file.</param>
        /// <param name="materials">
        /// The non-null encryption materials to be used to encrypt and decrypt Envelope key.
        /// </param>
        /// <returns>
        /// A non-null instruction object containing encryption information.
        /// </returns>
        internal static EncryptionInstructions BuildInstructionsForNonKmsV3InInstructionMode(MetadataCollection objectMetaData, Dictionary<string, string> pairsFromInsFile, EncryptionMaterialsBase materials)
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //= type=exception
            //# The S3EC SHOULD support decoding the S3 Server's "double encoding".
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
            if (!ContentMetaDataV3Utils.IsV3ObjectInInstructionFileMode(pairsFromInsFile))
            {
                throw new InvalidDataException("Missing parameters in instruction file required for decryption." + 
                                               $"Instruction files requires {ContentMetaDataV3Utils.EncryptedDataKeyV3} and {ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3} for V3 object.");
            }
            EnsureSupportedAlgorithmsV3(objectMetaData, pairsFromInsFile);
            var encryptedEnvelopeKey = Base64DecodedDataValue(pairsFromInsFile, ContentMetaDataV3Utils.EncryptedDataKeyV3);
            var messageId = Convert.FromBase64String(objectMetaData[ContentMetaDataV3Utils.MessageIdV3]);
            Dictionary<string, string> materialDescription;
            Dictionary<string, string> encryptionContext;
            // Instruction file is only available for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`). So, this annotation can be assumed safely. 
            //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
            //= type=implication
            //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
            if (objectMetaData[ContentMetaDataV3Utils.MatDescV3] != null)
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=exception
                //# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
                materialDescription = JsonUtils.ToDictionary(pairsFromInsFile[ContentMetaDataV3Utils.MatDescV3]);
            else 
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# If the mapkey is not present, the default Material Description value MUST be set to an empty map (`{}`).
                materialDescription = new Dictionary<string, string>();
            if (objectMetaData[ContentMetaDataV3Utils.EncryptionContextV3] != null)
            {
                encryptionContext = JsonUtils.ToDictionary(pairsFromInsFile[ContentMetaDataV3Utils.EncryptionContextV3]);
            }
            else
            {
                encryptionContext = new Dictionary<string, string>();
            }
            var cekAlgorithm = objectMetaData[ContentMetaDataV3Utils.ContentCipherV3];
            var wrapAlgorithm = ContentMetaDataV3Utils.ExpandV3WrapAlgorithm(StringValue(pairsFromInsFile, ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3));
            var keyCommitment = Convert.FromBase64String(objectMetaData[ContentMetaDataV3Utils.KeyCommitmentV3]);
            return BuildEncInstructionsForV3Object(encryptedEnvelopeKey, messageId, wrapAlgorithm, 
                encryptionContext, materialDescription, materials, null, keyCommitment, AlgorithmSuite.AlgAes256GcmHkdfSha512CommitKey);
        }
        
        /// <summary>
        /// Converts encryption context JSON string to dictionary
        /// </summary>
        /// <param name="metadata">Metadata that contains x-amz-t key</param>
        /// <returns></returns>
        internal static Dictionary<string, string> GetEncryptionContextFromMetaData(MetadataCollection metadata)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
            //= type=exception
            //# This encryption context string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
            
            if (!ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata))
            {
                return GetMaterialDescriptionFromMetaData(metadata);
            }

            var ecJsonString = metadata[ContentMetaDataV3Utils.EncryptionContextV3];
            if (ecJsonString == null)
            {
                return new Dictionary<string, string>();
            }

            var ec = JsonUtils.ToDictionary(ecJsonString);
            return ec;
        }
    }
}
