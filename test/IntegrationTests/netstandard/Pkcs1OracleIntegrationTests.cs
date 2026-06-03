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
    /// Integration tests verifying that security profiles which forbid legacy reads
    /// reject V1 metadata BEFORE performing the RSA private key operation.
    ///
    /// Expected behavior (after fix):
    ///   Both valid and invalid PKCS#1v1.5 ciphertexts produce the same AmazonCryptoException
    ///   when legacy reads are disabled — eliminating the Bleichenbacher padding oracle.
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
            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(_vanillaS3, _bucketName));
            _vanillaS3.Dispose();
            _rsa.Dispose();
            base.Dispose(disposing);
        }

        // ═══════════════════════════════════════════════════════════════════
        // V2 + ForbidEncryptAllowDecrypt + AesGcm
        // Must reject V1 metadata before RSA decrypt — no oracle
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V2_ForbidEncryptAllowDecrypt_AesGcm_NoOracle()
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(
                CreateV2Config(SecurityProfile.V2));

            Assert.IsType<AmazonCryptoException>(errorForRandomCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // V4 + ForbidEncryptAllowDecrypt + AesGcm
        // Must reject V1 metadata before RSA decrypt — no oracle
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_ForbidEncryptAllowDecrypt_AesGcm_NoOracle()
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(
                CreateV4Config(SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm));

            Assert.IsType<AmazonCryptoException>(errorForRandomCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // V4 + RequireEncryptAllowDecrypt + AesGcmWithCommitment
        // Must reject V1 metadata before RSA decrypt — no oracle
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptAllowDecrypt_AesGcmWithCommitment_NoOracle()
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(
                CreateV4Config(SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment));

            Assert.IsType<AmazonCryptoException>(errorForRandomCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // V4 + RequireEncryptRequireDecrypt + AesGcmWithCommitment
        // Commitment check fires before unwrap
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptRequireDecrypt_AesGcmWithCommitment_NoOracle()
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(
                CreateV4Config(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment));

            Assert.IsType<ArgumentException>(errorForRandomCiphertext);
            Assert.IsType<ArgumentException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("The requested object is encrypted with non key committing algorithm", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Helpers
        // ═══════════════════════════════════════════════════════════════════

        private static AmazonS3CryptoConfigurationV2 CreateV2Config(SecurityProfile profile) =>
            new AmazonS3CryptoConfigurationV2(profile, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            { StorageMode = CryptoStorageMode.ObjectMetadata };

        private static AmazonS3CryptoConfigurationV4 CreateV4Config(SecurityProfile profile, CommitmentPolicy commitment, ContentEncryptionAlgorithm algo) =>
            new AmazonS3CryptoConfigurationV4(profile, commitment, algo)
            { StorageMode = CryptoStorageMode.ObjectMetadata };

        private async Task<(Exception errorForRandomCiphertext, Exception errorForValidCiphertext)> RunOracleTest(
            AmazonS3CryptoConfigurationBase decryptConfig)
        {
            var prefix = $"pkcs1-oracle/{Guid.NewGuid():N}";
            var isV4 = decryptConfig is AmazonS3CryptoConfigurationV4;

            // Step 1: Encrypt with V2 (RSA-OAEP)
            var originalKey = $"{prefix}/original.txt";
            var encConfig = CreateV2Config(SecurityProfile.V2);
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

            // Step 2: Read raw metadata and body
            var meta = await _vanillaS3.GetObjectMetadataAsync(_bucketName, originalKey);
            var iv = meta.Metadata["x-amz-iv"];
            var matdesc = meta.Metadata["x-amz-matdesc"] ?? "{}";

            var rawObj = await _vanillaS3.GetObjectAsync(_bucketName, originalKey);
            using var ms = new MemoryStream();
            await rawObj.ResponseStream.CopyToAsync(ms);
            var rawBody = ms.ToArray();

            // Step 3a: Upload with random ciphertext (invalid PKCS#1v1.5 padding)
            byte[] randomCiphertext = new byte[_rsa.KeySize / 8];
            RandomNumberGenerator.Fill(randomCiphertext);
            var randomKey = $"{prefix}/random-ciphertext.txt";
            await UploadV1Object(randomKey, rawBody, Convert.ToBase64String(randomCiphertext), iv, matdesc);

            // Step 3b: Upload with valid PKCS#1v1.5 ciphertext
            byte[] validCiphertext = _rsa.Encrypt(new byte[32], RSAEncryptionPadding.Pkcs1);
            var validKey = $"{prefix}/valid-ciphertext.txt";
            await UploadV1Object(validKey, rawBody, Convert.ToBase64String(validCiphertext), iv, matdesc);

            // Step 4: Attempt decrypt
            var errorForRandom = await AttemptDecrypt(decryptConfig, isV4, randomKey);
            var errorForValid = await AttemptDecrypt(decryptConfig, isV4, validKey);

            return (errorForRandom, errorForValid);
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

        private async Task<Exception> AttemptDecrypt(AmazonS3CryptoConfigurationBase config, bool isV4, string key)
        {
            try
            {
                if (isV4)
                {
                    var materials = new EncryptionMaterialsV4(_rsa, AsymmetricAlgorithmType.RsaOaepSha1);
                    using var client = new AmazonS3EncryptionClientV4((AmazonS3CryptoConfigurationV4)config, materials);
                    var resp = await client.GetObjectAsync(_bucketName, key);
                    using var reader = new StreamReader(resp.ResponseStream);
                    await reader.ReadToEndAsync();
                }
                else
                {
                    var materials = new EncryptionMaterialsV2(_rsa, AsymmetricAlgorithmType.RsaOaepSha1);
                    using var client = new AmazonS3EncryptionClientV2((AmazonS3CryptoConfigurationV2)config, materials);
                    var resp = await client.GetObjectAsync(_bucketName, key);
                    using var reader = new StreamReader(resp.ResponseStream);
                    await reader.ReadToEndAsync();
                }
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
