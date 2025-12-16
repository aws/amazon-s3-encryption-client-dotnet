using System.Collections.Generic;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3.Model;
using Moq;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class EncryptionUtilsV2Tests
    {
        [Fact]
        public void UpdateMetadataWithEncryptionInstructionsV2_WithPutObjectRequest_ShouldAddAllV2Metadata()
        {
            var request = new PutObjectRequest();
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string>(),
                new byte[32],
                new byte[16],
                new byte[16],
                "kms+context",
                AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf);

            EncryptionUtils.UpdateMetadataWithEncryptionInstructionsV2(request, instructions);
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=test
            //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.

            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-wrap-alg"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-tag-len"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-key-v2"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-cek-alg"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-iv"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
            Assert.NotNull(request.Metadata["x-amz-matdesc"]);
        }
        
        [Fact]
        public void CreateInstructionFileRequestV2_ShouldContainAllRequiredV2Metadata()
        {
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
            //= type=test
            //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=test
            //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
            var request = new PutObjectRequest { BucketName = "test-bucket", Key = "test-key" };
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string>(), 
                new byte[32], 
                new byte[16], 
                new byte[16], 
                "kms+context", 
                AlgorithmSuite.AlgAes256GcmIv12Tag16NoKdf);

            var result = EncryptionUtils.CreateInstructionFileRequestV2(request, instructions);
            var contentJson = JsonUtils.ToDictionary(result.ContentBody);

            Assert.Contains("x-amz-tag-len", contentJson.Keys);
            Assert.Contains("x-amz-key-v2", contentJson.Keys);
            Assert.Contains("x-amz-cek-alg", contentJson.Keys);
            Assert.Contains("x-amz-wrap-alg", contentJson.Keys);
            Assert.Contains("x-amz-iv", contentJson.Keys);
            Assert.Contains("x-amz-matdesc", contentJson.Keys);
        }
    }
}