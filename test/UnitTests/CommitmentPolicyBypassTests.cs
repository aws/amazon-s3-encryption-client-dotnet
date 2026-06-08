using System;
using System.Collections.Generic;
using Amazon.Extensions.S3.Encryption.Internal;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;
using Amazon.S3.Model;
using Moq;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    /// <summary>
    /// Tests that verify the commitment policy cannot be bypassed by attacker-controlled metadata.
    /// 
    /// Threat model: S3 server or MITM is untrusted. An attacker can inject arbitrary headers
    /// on a V2 (non-committed) ciphertext response. The commitment policy gate must reject
    /// any object that has V1/V2 envelope keys present, regardless of spoofed V3 headers.
    /// </summary>
    public class CommitmentPolicyBypassTests
    {
        private static readonly EncryptionMaterialsV4 Materials =
            new EncryptionMaterialsV4("dummy-key-id", KmsType.KmsContext, new Dictionary<string, string>());

        private static readonly AmazonS3CryptoConfigurationV4 RequireDecryptConfig =
            new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);

        private static readonly AmazonS3CryptoConfigurationV4 AllowDecryptConfig =
            new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);

        /// <summary>
        /// Invokes the actual ThrowIfDecryptNonCommitingDisabled method on SetupDecryptionHandlerV4.
        /// </summary>
        private static void InvokeThrowIfDecryptNonCommitingDisabled(
            AmazonS3CryptoConfigurationV4 config, MetadataCollection metadata)
        {
            var client = new AmazonS3EncryptionClientV4(config, Materials);
            var handler = new Mock<SetupDecryptionHandlerV4>(client);
            handler.CallBase = true;

            Utils.RunInstanceMethod(
                typeof(SetupDecryptionHandlerV4),
                "ThrowIfDecryptNonCommitingDisabled",
                handler.Object,
                new object[] { metadata });
        }

        #region IsV3Object detection tests

        [Fact]
        public void IsV3Object_WithAllThreeRequiredHeaders_ReturnsTrue()
        {
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "base64commitment";
            metadata["x-amz-i"] = "base64messageid";

            Assert.True(ContentMetaDataV3Utils.IsV3Object(metadata));
        }

        [Fact]
        public void IsV3Object_WithOnlyContentCipher_ReturnsFalse()
        {
            // Attacker injects only x-amz-c on a V2 object
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";

            Assert.False(ContentMetaDataV3Utils.IsV3Object(metadata));
        }

        [Fact]
        public void IsV3Object_WithContentCipherAndKeyCommitment_ReturnsFalse()
        {
            // Attacker injects x-amz-c and x-amz-d but not x-amz-i
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "garbage";

            Assert.False(ContentMetaDataV3Utils.IsV3Object(metadata));
        }

        [Fact]
        public void IsV3Object_WithContentCipherAndMessageId_ReturnsFalse()
        {
            // Attacker injects x-amz-c and x-amz-i but not x-amz-d
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-i"] = "garbage";

            Assert.False(ContentMetaDataV3Utils.IsV3Object(metadata));
        }

        [Fact]
        public void IsV3Object_EmptyMetadata_ReturnsFalse()
        {
            var metadata = new MetadataCollection();
            Assert.False(ContentMetaDataV3Utils.IsV3Object(metadata));
        }

        #endregion

        #region Commitment policy bypass attack scenarios — calls actual ThrowIfDecryptNonCommitingDisabled

        [Fact]
        public void CommitmentGate_V2ObjectWithSpoofedContentCipherOnly_MustThrow()
        {
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            var metadata = CreateV2Metadata();
            metadata["x-amz-c"] = "115"; // attacker injects single V3 header

            // Any V3 key alongside V1/V2 keys → throws per spec exclusive key rule
            Assert.ThrowsAny<Exception>(() =>
                InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata));
        }

        [Fact]
        public void CommitmentGate_V2ObjectWithSpoofedContentCipherAndKeyCommitment_MustThrow()
        {
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.
            var metadata = CreateV2Metadata();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "fakecommitment";

            // Any V3 key alongside V1/V2 keys → throws per spec exclusive key rule
            Assert.ThrowsAny<Exception>(() =>
                InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata));
        }

        [Fact]
        public void CommitmentGate_V2ObjectWithAllV3HeadersSpoofed_MustThrow()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
            var metadata = CreateV2Metadata();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "fakecommitment";
            metadata["x-amz-i"] = "fakemessageid";

            // IsV3Object detects V3 markers + V1/V2 keys → throws InvalidDataException per spec
            Assert.ThrowsAny<Exception>(() =>
                InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata));
        }

        [Fact]
        public void CommitmentGate_V1ObjectWithAllV3HeadersSpoofed_MustThrow()
        {
            var metadata = new MetadataCollection();
            metadata["x-amz-key"] = "base64encryptedkey";
            metadata["x-amz-iv"] = "base64iv";
            metadata["x-amz-matdesc"] = "{}";
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "fakecommitment";
            metadata["x-amz-i"] = "fakemessageid";

            // IsV3Object detects V3 markers + V1/V2 keys → throws InvalidDataException per spec
            Assert.ThrowsAny<Exception>(() =>
                InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata));
        }

        [Fact]
        public void CommitmentGate_LegitimateV3MetadataMode_MustNotThrow()
        {
            // Legitimate V3 object: has V3 headers and NO V1/V2 keys
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "realcommitment";
            metadata["x-amz-i"] = "realmessageid";
            metadata["x-amz-3"] = "realencryptedkey";
            metadata["x-amz-w"] = "12";

            // Should not throw
            InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata);
        }

        [Fact]
        public void CommitmentGate_LegitimateV3InstructionFileMode_MustNotThrow()
        {
            // In instruction file mode: x-amz-c/d/i in metadata, x-amz-3 NOT in metadata
            // No V1/V2 keys present
            var metadata = new MetadataCollection();
            metadata["x-amz-c"] = "115";
            metadata["x-amz-d"] = "realcommitment";
            metadata["x-amz-i"] = "realmessageid";

            // Should not throw
            InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata);
        }

        [Fact]
        public void CommitmentGate_V2ObjectNoSpoofedHeaders_MustThrow()
        {
            // Normal V2 object — policy must reject
            var metadata = CreateV2Metadata();

            Assert.Throws<ArgumentException>(() =>
                InvokeThrowIfDecryptNonCommitingDisabled(RequireDecryptConfig, metadata));
        }

        [Fact]
        public void CommitmentGate_V2ObjectWithAllowDecryptPolicy_MustNotThrow()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            var metadata = CreateV2Metadata();

            // Should not throw with REQUIRE_ENCRYPT_ALLOW_DECRYPT
            InvokeThrowIfDecryptNonCommitingDisabled(AllowDecryptConfig, metadata);
        }

        #endregion

        #region Helpers

        private static MetadataCollection CreateV2Metadata()
        {
            var metadata = new MetadataCollection();
            metadata["x-amz-key-v2"] = "base64encryptedkey";
            metadata["x-amz-iv"] = "base64iv";
            metadata["x-amz-cek-alg"] = "AES/GCM/NoPadding";
            metadata["x-amz-wrap-alg"] = "kms+context";
            metadata["x-amz-tag-len"] = "128";
            metadata["x-amz-matdesc"] = "{}";
            return metadata;
        }

        #endregion
    }
}
