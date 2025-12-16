using System;
using System.Collections.Generic;
using System.IO;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.S3.Model;
using ThirdParty.Json.LitJson;
using Xunit;
using Xunit.Extensions;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class ContentMetaDataV3Tests
    {
        private MetadataCollection CreateValidMetadata(bool isNonKmsKeyringMaterial)
        {
            var metadata = new MetadataCollection();
            metadata[ContentMetaDataV3Utils.ContentCipherV3] = "115";
            metadata[ContentMetaDataV3Utils.EncryptedDataKeyV3] = "base64key";
            metadata[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3] = "12";
            metadata[ContentMetaDataV3Utils.KeyCommitmentV3] = "base64commitment";
            metadata[ContentMetaDataV3Utils.MessageIdV3] = "base64messageid";

            if (isNonKmsKeyringMaterial)
                metadata[ContentMetaDataV3Utils.MatDescV3] = "{}";
            else
                metadata[ContentMetaDataV3Utils.EncryptionContextV3] = "{\"aws:x-amz-cek-alg\":\"115\"}";

            return metadata;
        }

        private JsonData CreateValidInstructionFile()
        {
            var instructionFile = new JsonData();
            instructionFile[ContentMetaDataV3Utils.EncryptedDataKeyV3] = "base64key";
            instructionFile[ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3] = "12";
            instructionFile[ContentMetaDataV3Utils.MatDescV3] = "{}";
            return instructionFile;
        }

        private MetadataCollection CreateValidObjectMetadataForInstructionFile()
        {
            var metadata = new MetadataCollection();
            metadata[ContentMetaDataV3Utils.ContentCipherV3] = "115";
            metadata[ContentMetaDataV3Utils.KeyCommitmentV3] = "base64commitment";
            metadata[ContentMetaDataV3Utils.MessageIdV3] = "base64messageid";
            return metadata;
        }

        [Fact]
        public void ValidateV3Metadata_ValidNonKmsKeyring_DoesNotThrow()
        {
            var metadata = CreateValidMetadata(true);
            ContentMetaDataV3Utils.ValidateV3ObjectMetadata(metadata, true);
        }

        [Fact]
        public void ValidateV3Metadata_ValidKmsKeyring_DoesNotThrow()
        {
            var metadata = CreateValidMetadata(false);
            ContentMetaDataV3Utils.ValidateV3ObjectMetadata(metadata, false);
        }

        [Theory]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
        [InlineData(ContentMetaDataV3Utils.ContentCipherV3, true)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
        [InlineData(ContentMetaDataV3Utils.EncryptedDataKeyV3, true)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
        [InlineData(ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3, true)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
        [InlineData(ContentMetaDataV3Utils.KeyCommitmentV3, true)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
        [InlineData(ContentMetaDataV3Utils.MessageIdV3, true)]
        public void ValidateV3Metadata_MissingRequiredField_ThrowsException(string missingKey, bool isNonKmsKeyring)
        {
            var metadata = CreateValidMetadata(isNonKmsKeyring);
            metadata[missingKey] = null;
            Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.ValidateV3ObjectMetadata(metadata, isNonKmsKeyring));
        }

        [Fact]
        public void ValidateV3InstructionFile_Valid_DoesNotThrow()
        {
            var objectMetadata = CreateValidObjectMetadataForInstructionFile();
            var instructionFile = CreateValidInstructionFile();
            ContentMetaDataV3Utils.ValidateV3InstructionFile(objectMetadata, instructionFile);
        }

        [Theory]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
        [InlineData(ContentMetaDataV3Utils.ContentCipherV3)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
        [InlineData(ContentMetaDataV3Utils.KeyCommitmentV3)]
        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
        [InlineData(ContentMetaDataV3Utils.MessageIdV3)]
        public void ValidateV3InstructionFile_MissingRequiredObjectMetadata_ThrowsException(string missingKey)
        {
            var objectMetadata = CreateValidObjectMetadataForInstructionFile();
            var instructionFile = CreateValidInstructionFile();
            objectMetadata[missingKey] = null;
            Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.ValidateV3InstructionFile(objectMetadata, instructionFile));
        }

        [Theory]
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
        [InlineData(ContentMetaDataV3Utils.ContentCipherV3)]
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
        [InlineData(ContentMetaDataV3Utils.KeyCommitmentV3)]
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
        [InlineData(ContentMetaDataV3Utils.MessageIdV3)]
        public void ValidateV3InstructionFile_ForbiddenKeysInInstructionFile_ThrowsException(string forbiddenKey)
        {
            var objectMetadata = CreateValidObjectMetadataForInstructionFile();
            var instructionFile = CreateValidInstructionFile();
            instructionFile[forbiddenKey] = "value";
            Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.ValidateV3InstructionFile(objectMetadata, instructionFile));
        }

        [Theory]
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
        [InlineData(ContentMetaDataV3Utils.EncryptedDataKeyV3)]
        //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
        [InlineData(ContentMetaDataV3Utils.EncryptedDataKeyAlgorithmV3)]
        public void ValidateV3InstructionFile_MissingRequiredInstructionFileKey_ThrowsException(string missingKey)
        {
            var objectMetadata = CreateValidObjectMetadataForInstructionFile();
            var instructionFile = CreateValidInstructionFile();
            instructionFile[missingKey] = null;
            Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.ValidateV3InstructionFile(objectMetadata, instructionFile));
        }

        [Fact]
        public void ValidateV3InstructionFile_EncryptionContextPresent_ThrowsUnsupportedOperationException()
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //= type=exception
            //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
            var objectMetadata = CreateValidObjectMetadataForInstructionFile();
            var instructionFile = CreateValidInstructionFile();
            instructionFile[ContentMetaDataV3Utils.EncryptionContextV3] = "{}";
            Assert.Throws<NotSupportedException>(() =>
                ContentMetaDataV3Utils.ValidateV3InstructionFile(objectMetadata, instructionFile));
        }

        [Theory]
        [InlineData("x-amz-key")]
        [InlineData("x-amz-key-v2")]
        public void EnsureUniqueMetaDataForV3InMetadataMode_WithV1V2Keys_ShouldThrowException(string conflictingKey)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=test
            //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
            var metadata = new MetadataCollection();
            metadata.Add(conflictingKey, "value");
            metadata.Add("x-amz-3", "v3key");

            var exception = Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.EnsureUniqueMetaDataForV3InMetadataMode(metadata));

            Assert.Contains("V3 objects should not have v2 or v1 metadata keys", exception.Message);
        }

        [Fact]
        public void EnsureUniqueMetaDataForV3InMetadataMode_WithNoV1V2Keys_ShouldSucceed()
        {
            var metadata = new MetadataCollection();
            metadata.Add("x-amz-c", "115");
            metadata.Add("x-amz-3", "somekey");

            ContentMetaDataV3Utils.EnsureUniqueMetaDataForV3InMetadataMode(metadata);
        }

        [Theory]
        [InlineData("x-amz-key", true, false)]
        [InlineData("x-amz-key-v2", true, false)]
        [InlineData("x-amz-key", false, true)]
        [InlineData("x-amz-key-v2", false, true)]
        public void EnsureUniqueMetaDataForV3InInstructionFile_WithConflicts_ShouldThrowException(
            string conflictingKey, bool inMetadata, bool inInstructionFile)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=test
            //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
            var objectMetadata = new MetadataCollection();
            var instructionFile = new JsonData();

            if (inMetadata) objectMetadata.Add(conflictingKey, "value");
            if (inInstructionFile) instructionFile[conflictingKey] = "value";

            var exception = Assert.Throws<InvalidDataException>(() =>
                ContentMetaDataV3Utils.EnsureUniqueMetaDataForV3InInstructionFile(objectMetadata, instructionFile));

            var expectedMessage =
                inMetadata ? "object metadata contains conflicting" : "instruction file contains conflicting";
            Assert.Contains(expectedMessage, exception.Message);
        }

        [Fact]
        public void EnsureUniqueMetaDataForV3InInstructionFile_WithNoConflicts_ShouldSucceed()
        {
            var objectMetadata = new MetadataCollection();
            objectMetadata.Add("x-amz-c", "115");
            var instructionFile = new JsonData();
            instructionFile["x-amz-3"] = "v3key";

            ContentMetaDataV3Utils.EnsureUniqueMetaDataForV3InInstructionFile(objectMetadata, instructionFile);
        }
        
        [Fact]
        public void IsV3ObjectInMetaDataMode_WithAllRequiredKeys_ShouldReturnTrue()
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=test
            //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
            var metadata = new MetadataCollection();
            metadata.Add("x-amz-3", "key");
            metadata.Add("x-amz-d", "commitment");
            metadata.Add("x-amz-i", "messageid");

            var result = ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata);

            Assert.True(result);
        }

        [Theory]
        [InlineData("x-amz-3")]
        [InlineData("x-amz-d")]
        [InlineData("x-amz-i")]
        public void IsV3ObjectInMetaDataMode_WithMissingRequiredKey_ShouldReturnFalse(string missingKey)
        {
            //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //= type=test
            //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
            var metadata = new MetadataCollection();
            metadata.Add("x-amz-3", "key");
            metadata.Add("x-amz-d", "commitment");
            metadata.Add("x-amz-i", "messageid");
            metadata[missingKey] = null;

            var result = ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata);

            Assert.False(result);
        }

        [Fact]
        public void IsV3ObjectInMetaDataMode_WithEmptyMetadata_ShouldReturnFalse()
        {
            var metadata = new MetadataCollection();

            var result = ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(metadata);

            Assert.False(result);
        }

    }
}