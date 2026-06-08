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
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
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
            EncryptionTestsUtils.CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(_vanillaS3, _bucketName));
            _vanillaS3.Dispose();
            _rsa.Dispose();
            base.Dispose(disposing);
        }

        // ═══════════════════════════════════════════════════════════════════
        // SecurityProfile.V2: V1 metadata must be rejected before RSA decrypt.
        // Both valid and invalid padding ciphertexts must produce the SAME error
        // (AmazonCryptoException from the legacy gate), proving no oracle exists.
        // ═══════════════════════════════════════════════════════════════════
        public static IEnumerable<object[]> OracleTestCases()
        {
            yield return new object[] { CryptoStorageMode.ObjectMetadata };
            yield return new object[] { CryptoStorageMode.InstructionFile };
        }

        [Theory]
        [Trait(CategoryAttribute, "S3")]
        [MemberData(nameof(OracleTestCases))]
        public async Task V2_RejectsV1BeforeRsaDecrypt_NoOracle(CryptoStorageMode storageMode)
        {
            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(SecurityProfile.V2, storageMode);

            Assert.NotNull(errorForRandomCiphertext);
            Assert.NotNull(errorForValidCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForRandomCiphertext);
            Assert.IsType<AmazonCryptoException>(errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Helper
        // ═══════════════════════════════════════════════════════════════════

        private async Task<(Exception errorForRandomCiphertext, Exception errorForValidCiphertext)> RunOracleTest(
            SecurityProfile securityProfile,
            CryptoStorageMode storageMode = CryptoStorageMode.ObjectMetadata)
        {
            var prefix = $"pkcs1-oracle/{Guid.NewGuid():N}";

            // Encrypt with V2 (RSA-OAEP) — the oracle test targets the decryption path, so the encrypting client doesn't matter.
            var originalKey = $"{prefix}/original.txt";
            var encConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = storageMode
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

            // Read IV and matdesc from the encrypted object
            string iv, matdesc;
            if (storageMode == CryptoStorageMode.InstructionFile)
            {
                using var instrFileResp = await _vanillaS3.GetObjectAsync(_bucketName, originalKey + ".instruction");
                using var instrReader = new StreamReader(instrFileResp.ResponseStream);
                var instrContent = await instrReader.ReadToEndAsync();
                var instrDict = JsonSerializer.Deserialize<Dictionary<string, string>>(instrContent);
                iv = instrDict["x-amz-iv"];
                matdesc = instrDict.ContainsKey("x-amz-matdesc") ? instrDict["x-amz-matdesc"] : "{}";
            }
            else
            {
                var meta = await _vanillaS3.GetObjectMetadataAsync(_bucketName, originalKey);
                iv = meta.Metadata["x-amz-iv"];
                matdesc = meta.Metadata["x-amz-matdesc"] ?? "{}";
            }

            // Read raw encrypted body
            using var rawObj = await _vanillaS3.GetObjectAsync(_bucketName, originalKey);
            using var ms = new MemoryStream();
            await rawObj.ResponseStream.CopyToAsync(ms);
            var rawBody = ms.ToArray();

            // Upload with INVALID PKCS#1v1.5 padding (random bytes)
            byte[] invalidCiphertext = new byte[_rsa.KeySize / 8];
            RandomNumberGenerator.Fill(invalidCiphertext);
            var invalidKey = $"{prefix}/invalid-padding.txt";
            await UploadV1Object(invalidKey, rawBody, Convert.ToBase64String(invalidCiphertext), iv, matdesc, storageMode);

            // Upload with VALID PKCS#1v1.5 padding
            byte[] validCiphertext = _rsa.Encrypt(new byte[32], RSAEncryptionPadding.Pkcs1);
            var validKey = $"{prefix}/valid-padding.txt";
            await UploadV1Object(validKey, rawBody, Convert.ToBase64String(validCiphertext), iv, matdesc, storageMode);

            // Attempt decrypt with the given security profile
            var errorForRandomCiphertext = await AttemptDecrypt(securityProfile, invalidKey, storageMode);
            var errorForValidCiphertext = await AttemptDecrypt(securityProfile, validKey, storageMode);

            Assert.NotNull(errorForRandomCiphertext);
            Assert.NotNull(errorForValidCiphertext);
            return (errorForRandomCiphertext, errorForValidCiphertext);
        }

        private async Task UploadV1Object(string key, byte[] body, string wrappedKeyBase64, string iv, string matdesc,
            CryptoStorageMode storageMode)
        {
            if (storageMode == CryptoStorageMode.InstructionFile)
            {
                // Upload body with no encryption metadata
                await _vanillaS3.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = _bucketName,
                    Key = key,
                    InputStream = new MemoryStream(body)
                });

                // Upload V1 instruction file as JSON
                var instrDict = new Dictionary<string, string>
                {
                    { "x-amz-key", wrappedKeyBase64 },
                    { "x-amz-iv", iv },
                    { "x-amz-matdesc", matdesc }
                };
                await _vanillaS3.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = _bucketName,
                    Key = key + ".instruction",
                    ContentBody = JsonSerializer.Serialize(instrDict)
                });
            }
            else
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
        }

        private async Task<Exception> AttemptDecrypt(SecurityProfile securityProfile, string key,
            CryptoStorageMode storageMode = CryptoStorageMode.ObjectMetadata)
        {
            // V2 only supports ForbidEncryptAllowDecrypt with AesGcm (no key commitment)
            var config = new AmazonS3CryptoConfigurationV2(securityProfile,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = storageMode
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
                // Unwrap to innermost: the AWS SDK pipeline infrastructure wraps exceptions
                // thrown by pipeline handlers (like our decryption handler) in AmazonS3Exception.
                // We assert on the root cause to verify the security gate fired correctly.
                var inner = ex;
                while (inner.InnerException != null) inner = inner.InnerException;
                return inner;
            }
        }
    }
}
