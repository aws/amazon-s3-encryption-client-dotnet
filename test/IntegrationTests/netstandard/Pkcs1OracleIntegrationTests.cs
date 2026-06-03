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
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.S3;
using Amazon.S3.Model;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    /// <summary>
    /// Integration tests verifying that SecurityProfile.V2 rejects V1 metadata
    /// BEFORE performing the RSA private key operation.
    ///
    /// Expected behavior:
    ///   When V1 metadata is encountered with SecurityProfile.V2, the legacy gate
    ///   (ThrowIfLegacyReadIsDisabled) must fire BEFORE BuildInstructionsFromObjectMetadata
    ///   so that both valid and invalid PKCS#1v1.5 ciphertexts produce the same
    ///   AmazonCryptoException — eliminating the Bleichenbacher padding oracle.
    /// </summary>
    public class Pkcs1OracleIntegrationTests : TestBase<AmazonS3Client>
    {
        private readonly RSA _rsa = RSA.Create(2048);
        private readonly AmazonS3Client _vanillaS3 = new AmazonS3Client();
        private readonly string _bucketName;

        public Pkcs1OracleIntegrationTests(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            _bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(_vanillaS3));
        }

        protected override void Dispose(bool disposing)
        {
            // EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(_vanillaS3, _bucketName));
            _vanillaS3.Dispose();
            _rsa.Dispose();
            base.Dispose(disposing);
        }

        // ═══════════════════════════════════════════════════════════════════
        // SecurityProfile.V2: V1 metadata must be rejected before RSA decrypt.
        // Both valid and invalid padding ciphertexts must produce the SAME error
        // (AmazonCryptoException from the legacy gate), proving no oracle exists.
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V2_RejectsV1MetadataBeforeRsaDecrypt_NoOracle()
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(SecurityProfile.V2);

            // Both V1 objects must be rejected with AmazonCryptoException (legacy gate)
            // regardless of what ciphertext is in x-amz-key — the RSA operation should never run
            Assert.IsType<AmazonCryptoException>(errorForRandomCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.GetType(), errorForValidCiphertext.GetType());
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Helper
        // ═══════════════════════════════════════════════════════════════════

        private async Task<(Exception errorForRandomCiphertext, Exception errorForValidCiphertext)> RunOracleTest(
            SecurityProfile securityProfile)
        {
            var prefix = $"pkcs1-oracle/{Guid.NewGuid():N}";

            // Step 1: Encrypt with V2 (RSA-OAEP)
            var originalKey = $"{prefix}/original.txt";
            var encConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };
            var encMaterials = new EncryptionMaterialsV2(_rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            using (var encClient = new AmazonS3EncryptionClientV2(encConfig, encMaterials))
            {
                await encClient.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = _bucketName,
                    Key = originalKey,
                    ContentBody = "test data for oracle detection"
                });
            }

            // Step 2: Read raw metadata and body with vanilla client
            var meta = await _vanillaS3.GetObjectMetadataAsync(_bucketName, originalKey);
            var iv = meta.Metadata["x-amz-iv"];
            var matdesc = meta.Metadata["x-amz-matdesc"] ?? "{}";

            var rawObj = await _vanillaS3.GetObjectAsync(_bucketName, originalKey);
            using var ms = new MemoryStream();
            await rawObj.ResponseStream.CopyToAsync(ms);
            var rawBody = ms.ToArray();

            // Step 3a: Upload with INVALID PKCS#1v1.5 padding (random bytes as x-amz-key)
            byte[] invalidCiphertext = new byte[_rsa.KeySize / 8];
            RandomNumberGenerator.Fill(invalidCiphertext);
            var invalidKey = $"{prefix}/invalid-padding.txt";
            await UploadV1Object(invalidKey, rawBody, Convert.ToBase64String(invalidCiphertext), iv, matdesc);

            // Step 3b: Upload with VALID PKCS#1v1.5 padding
            byte[] validCiphertext = _rsa.Encrypt(new byte[32], RSAEncryptionPadding.Pkcs1);
            var validKey = $"{prefix}/valid-padding.txt";
            await UploadV1Object(validKey, rawBody, Convert.ToBase64String(validCiphertext), iv, matdesc);

            // Step 4: Attempt decrypt with the given security profile
            var errorForRandomCiphertext = await AttemptDecrypt(securityProfile, invalidKey);
            var errorForValidCiphertext = await AttemptDecrypt(securityProfile, validKey);

            return (errorForRandomCiphertext, errorForValidCiphertext);
        }

        private async Task UploadV1Object(string key, byte[] body, string wrappedKeyBase64, string iv, string matdesc)
        {
            var putReq = new PutObjectRequest
            {
                BucketName = _bucketName,
                Key = key,
                InputStream = new MemoryStream(body)
            };
            putReq.Metadata.Add("x-amz-key", wrappedKeyBase64);
            putReq.Metadata.Add("x-amz-iv", iv);
            putReq.Metadata.Add("x-amz-matdesc", matdesc);
            await _vanillaS3.PutObjectAsync(putReq);
        }

        private async Task<Exception> AttemptDecrypt(SecurityProfile securityProfile, string key)
        {
            var config = new AmazonS3CryptoConfigurationV2(securityProfile,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };
            var materials = new EncryptionMaterialsV2(_rsa, AsymmetricAlgorithmType.RsaOaepSha1);

            try
            {
                using var client = new AmazonS3EncryptionClientV2(config, materials);
                var resp = await client.GetObjectAsync(_bucketName, key);
                using var reader = new StreamReader(resp.ResponseStream);
                await reader.ReadToEndAsync();
                return null;
            }
            catch (Exception ex)
            {
                var inner = ex;
                while (inner.InnerException != null) inner = inner.InnerException;
                return inner;
            }
        }
    }
}
