using System.Collections.Generic;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3.Model;
using Xunit;
using Xunit.Extensions;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class EncryptionUtilsTests
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void UpdateMetadataWithEncryptionInstructions_ShouldSupportBothV1AndV2Formats(bool useV2Metadata)
        {
            var request = new PutObjectRequest();
            var instructions = new EncryptionInstructions(
                new Dictionary<string, string>(), 
                new byte[32], 
                new byte[16], 
                new byte[16], 
                "kms", 
                AlgorithmSuite.AlgAes256CbcIv16NoKdf);

            EncryptionUtils.UpdateMetadataWithEncryptionInstructions(request, instructions, useV2Metadata);
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
            //= type=test
            //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
            Assert.NotNull(request.Metadata["x-amz-iv"]);
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.
            Assert.NotNull(request.Metadata["x-amz-matdesc"]);

            if (useV2Metadata)
            {
                Assert.NotNull(request.Metadata["x-amz-key-v2"]);
                Assert.NotNull(request.Metadata["x-amz-wrap-alg"]);
                Assert.NotNull(request.Metadata["x-amz-cek-alg"]);
                Assert.Null(request.Metadata["x-amz-key"]);
            }
            else
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
                Assert.NotNull(request.Metadata["x-amz-key"]);
                Assert.Null(request.Metadata["x-amz-key-v2"]);
                Assert.Null(request.Metadata["x-amz-wrap-alg"]);
                Assert.Null(request.Metadata["x-amz-cek-alg"]);
            }
        }
    }
}