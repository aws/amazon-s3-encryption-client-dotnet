using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils
{
    // Content metadata are key value pairs added along with S3 object in metadata or instruction file mode.
    internal static class ContentMetaDataV3Utils
    {
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
        internal const string ContentCipherV3 = EncryptionUtils.XAmzPrefix + "c";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
        internal const string EncryptedDataKeyV3 = EncryptionUtils.XAmzPrefix + "3";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
        internal const string EncryptedDataKeyAlgorithmV3 = EncryptionUtils.XAmzPrefix + "w";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
        internal const string KeyCommitmentV3 = EncryptionUtils.XAmzPrefix + "d";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
        internal const string MessageIdV3 = EncryptionUtils.XAmzPrefix + "i";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
        internal const string MatDescV3 = EncryptionUtils.XAmzPrefix + "m";
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=implication
        //# - This mapkey ("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
        internal const string EncryptionContextV3 = EncryptionUtils.XAmzPrefix + "t";
        
        // v3 compressed algorithm values
        internal const string XAmzWrapAlgAesGcmV3 = "02";
        internal const string WrapAlgKmsContextV3 = "12";
        internal const string XAmzWrapAlgRsaOaepSha1V3 = "22";
        
        /// <summary>
        /// Determines if an object has V3 encryption schema (MetaData or Instruction File mode).
        /// </summary>
        /// <param name="objectMetadata">Object metadata collection</param>
        /// <returns>True if V3 format is detected</returns>
        internal static bool IsV3Object(
            MetadataCollection objectMetadata
        )
        {
            return objectMetadata[ContentCipherV3] != null;
        }
        
        /// <summary>
        /// Determines if an object has V3 encryption schema (Instruction File mode)
        /// </summary>
        /// <param name="instructionFileContent">Instruction file content</param>
        /// <returns>True if V3 format is detected</returns>
        internal static bool IsV3ObjectInInstructionFileMode(Dictionary<string, string> instructionFileContent)
        {
            var hasEncryptedKey = instructionFileContent.ContainsKey(EncryptedDataKeyV3);
            var hasAlgorithm = instructionFileContent.ContainsKey(EncryptedDataKeyAlgorithmV3);
    
            if (hasEncryptedKey != hasAlgorithm)
                throw new InvalidDataException($"Invalid metadata. The metadata is missing either {EncryptedDataKeyV3} or " +
                                               $"{EncryptedDataKeyAlgorithmV3} but not both.");
            
            return hasEncryptedKey;
        }
        
        internal static bool IsV3ObjectInMetaDataMode(
            MetadataCollection objectMetadata
        )
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
            return objectMetadata[EncryptedDataKeyV3] != null && objectMetadata[KeyCommitmentV3] != null &&
                   objectMetadata[MessageIdV3] != null;
        }
        
        internal static void ValidateV3ObjectMetadata(MetadataCollection metadata, bool isNonKmsMaterial)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
            if (metadata[ContentCipherV3] == null)
                throw new InvalidDataException($"V3 format requires {ContentCipherV3} metadata");
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
            if (metadata[EncryptedDataKeyV3] == null)
                throw new InvalidDataException($"V3 format requires {EncryptedDataKeyV3} metadata");
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
            if (metadata[EncryptedDataKeyAlgorithmV3] == null)
                throw new InvalidDataException($"V3 format requires {EncryptedDataKeyAlgorithmV3} metadata");
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
            if (metadata[KeyCommitmentV3] == null)
                throw new InvalidDataException($"V3 format requires {KeyCommitmentV3} metadata");
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
            if (metadata[MessageIdV3] == null)
                throw new InvalidDataException($"V3 format requires {MessageIdV3} metadata");

            EnsureUniqueMetaDataForV3InMetadataMode(metadata);
        }

        internal static void ValidateV3InstructionFile(MetadataCollection objectMetadata,
            Dictionary<string, string> instructionFileContent)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
            if (objectMetadata[ContentCipherV3] == null)
                throw new InvalidDataException(
                    $"V3 instruction file mode requires {ContentCipherV3} in object metadata");
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
            if (objectMetadata[KeyCommitmentV3] == null)
                throw new InvalidDataException(
                    $"V3 instruction file mode requires {KeyCommitmentV3} in object metadata");
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
            if (objectMetadata[MessageIdV3] == null)
                throw new InvalidDataException($"V3 instruction file mode requires {MessageIdV3} in object metadata");

            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.                                                                                                                                                                                                                                        
            if (instructionFileContent.ContainsKey(ContentCipherV3))
                throw new InvalidDataException(
                    $"V3 format violation: {ContentCipherV3} must not be in instruction file");
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
            if (instructionFileContent.ContainsKey(KeyCommitmentV3))
                throw new InvalidDataException(
                    $"V3 format violation: {KeyCommitmentV3} must not be in instruction file");
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
            if (instructionFileContent.ContainsKey(MessageIdV3))
                throw new InvalidDataException($"V3 format violation: {MessageIdV3} must not be in instruction file");

            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
            if (!instructionFileContent.ContainsKey(EncryptedDataKeyV3))
                throw new InvalidDataException($"V3 instruction file requires {EncryptedDataKeyV3}");
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
            if (!instructionFileContent.ContainsKey(EncryptedDataKeyAlgorithmV3))
                throw new InvalidDataException($"V3 instruction file requires {EncryptedDataKeyAlgorithmV3}");
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //= type=exception
            //# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
            if (instructionFileContent.ContainsKey(EncryptionContextV3))
                throw new NotSupportedException($"V3 instruction file contains {EncryptionContextV3} which is only a valid key for KMS wrapping key." +
                                                "KMS wrapping key with instruction file is an unsupported feature.");

            EnsureUniqueMetaDataForV3InInstructionFile(objectMetadata, instructionFileContent);
        }

        internal static void EnsureUniqueMetaDataForV3InMetadataMode(MetadataCollection metadata)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
            if (EncryptionUtils.V1V2Keys.Any(key => metadata[key] != null))
                throw new InvalidDataException("Invalid metadata. V3 objects should not have v2 or v1 metadata keys");
        }

        internal static void EnsureUniqueMetaDataForV3InInstructionFile(MetadataCollection objectMetadata, Dictionary<string, string> instructionFileContent)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=citation
            //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.                                                                                                                   
                                                                                                                                                                                                                                                                                             
            // Check for conflicting V1/V2 keys in object metadata                                                                                                                                                                                                                           
            if (EncryptionUtils.V1V2Keys.Any(key => objectMetadata[key] != null))                                                                                                                                                                                                                            
                throw new InvalidDataException("Invalid V3 instruction file: object metadata contains conflicting V1/V2 keys");                                                                                                                                                              
                                                                                                                                                                                                                                                                                             
            // Check for conflicting V1/V2 keys in instruction file
            if (EncryptionUtils.V1V2Keys.Any(key => instructionFileContent.ContainsKey(key)))
                throw new InvalidDataException("Invalid V3 instruction file: instruction file contains conflicting V1/V2 encrypted keys");
        }
        
        /// <summary>
        /// Compresses V2 wrap algorithm to V3 format
        /// </summary>
        /// <param name="algorithm">V2 wrap algorithm</param>
        /// <returns>V3 compressed algorithm</returns>
        internal static string CompressToV3WrapAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
                case EncryptionUtils.XAmzWrapAlgAesGcmValue:
                    return XAmzWrapAlgAesGcmV3;
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
                case EncryptionUtils.XAmzWrapAlgKmsContextValue:
                    return WrapAlgKmsContextV3;
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
                case EncryptionUtils.XAmzWrapAlgRsaOaepSha1:
                    return XAmzWrapAlgRsaOaepSha1V3;
                default:
                    throw new ArgumentException($"Unsupported wrap algorithm for V3: {algorithm}");
            }
        }

        /// <summary>
        /// Expands V3 compressed Wrap algorithm to V2 format
        /// </summary>
        /// <param name="compressed">V3 compressed Wrap algorithm</param>
        /// <returns>V2 wrap algorithm</returns>
        internal static string ExpandV3WrapAlgorithm(string compressed)
        {
            switch (compressed)
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
                case XAmzWrapAlgAesGcmV3:
                    return EncryptionUtils.XAmzWrapAlgAesGcmValue;
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
                case WrapAlgKmsContextV3:
                    return EncryptionUtils.XAmzWrapAlgKmsContextValue;
                //= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
                //= type=implication
                //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
                case XAmzWrapAlgRsaOaepSha1V3:
                    return EncryptionUtils.XAmzWrapAlgRsaOaepSha1;
                default:
                    throw new ArgumentException($"Unsupported V3 compressed algorithm: {compressed}");
            }
        }
    }
}