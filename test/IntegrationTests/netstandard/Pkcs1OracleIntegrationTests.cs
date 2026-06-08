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
    /// Integration tests verifying that security profiles which forbid legacy reads
    /// reject V1 metadata BEFORE performing the RSA private key operation.
    ///
    /// Expected behavior (after fix):
    ///   Both valid and invalid PKCS#1v1.5 ciphertexts produce the same AmazonCryptoException
    ///   when legacy reads are disabled — eliminating the Bleichenbacher padding oracle.
    /// </summary>
    [Collection(nameof(Pkcs1OracleIntegrationTests))]
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
        // Parameterized oracle test — covers all (config × storageMode) combos
        // ═══════════════════════════════════════════════════════════════════
        public static IEnumerable<object[]> OracleTestCases()
        {
            // V2 client only supports ForbidEncryptAllowDecrypt with AesGcm (no key commitment)
            // Metadata variants
            yield return new object[] { SecurityProfile.V2, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm, CryptoStorageMode.ObjectMetadata, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm, CryptoStorageMode.ObjectMetadata, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment, CryptoStorageMode.ObjectMetadata, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment, CryptoStorageMode.ObjectMetadata, typeof(ArgumentException), "The requested object is encrypted with non key committing algorithm" };
            // Instruction file variants
            yield return new object[] { SecurityProfile.V2, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm, CryptoStorageMode.InstructionFile, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm, CryptoStorageMode.InstructionFile, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment, CryptoStorageMode.InstructionFile, typeof(AmazonCryptoException), "V1 encryption schemas that have been disabled" };
            yield return new object[] { SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment, CryptoStorageMode.InstructionFile, typeof(ArgumentException), "The requested object is encrypted with non key committing algorithm" };
        }

        [Theory]
        [Trait(CategoryAttribute, "S3")]
        [MemberData(nameof(OracleTestCases))]
        public async Task NoOracleDistinguishableErrors(SecurityProfile securityProfile, CommitmentPolicy commitmentPolicy,
            ContentEncryptionAlgorithm algorithm, CryptoStorageMode storageMode, Type expectedExceptionType, string expectedMessage)
        {
            var config = securityProfile == SecurityProfile.V2
                ? (AmazonS3CryptoConfigurationBase)CreateV2Config(securityProfile, storageMode)
                : CreateV4Config(securityProfile, commitmentPolicy, algorithm, storageMode);

            var (errorForRandomCiphertext, errorForValidCiphertext) = await RunOracleTest(config);

            Assert.NotNull(errorForRandomCiphertext);
            Assert.NotNull(errorForValidCiphertext);
            Assert.IsType(expectedExceptionType, errorForRandomCiphertext);
            Assert.IsType(expectedExceptionType, errorForValidCiphertext);
            Assert.Equal(errorForRandomCiphertext.Message, errorForValidCiphertext.Message);
            Assert.Contains(expectedMessage, errorForRandomCiphertext.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Helpers
        // ═══════════════════════════════════════════════════════════════════

        private static AmazonS3CryptoConfigurationV2 CreateV2Config(SecurityProfile profile,
            CryptoStorageMode storageMode = CryptoStorageMode.ObjectMetadata) =>
            new AmazonS3CryptoConfigurationV2(profile, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            { StorageMode = storageMode };

        private static AmazonS3CryptoConfigurationV4 CreateV4Config(SecurityProfile profile, CommitmentPolicy commitment, ContentEncryptionAlgorithm algo,
            CryptoStorageMode storageMode = CryptoStorageMode.ObjectMetadata) =>
            new AmazonS3CryptoConfigurationV4(profile, commitment, algo)
            { StorageMode = storageMode };

        private async Task<(Exception errorForRandomCiphertext, Exception errorForValidCiphertext)> RunOracleTest(
            AmazonS3CryptoConfigurationBase decryptConfig)
        {
            var prefix = $"pkcs1-oracle/{Guid.NewGuid():N}";
            var isV4 = decryptConfig is AmazonS3CryptoConfigurationV4;
            var storageMode = decryptConfig.StorageMode;

            // Encrypt with V2 (RSA-OAEP) — the oracle test targets the decryption path, so the encrypting client doesn't matter. 
            var originalKey = $"{prefix}/original.txt";
            var encConfig = CreateV2Config(SecurityProfile.V2, storageMode);
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

            // Read IV and matdesc
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

            using var rawObj = await _vanillaS3.GetObjectAsync(_bucketName, originalKey);
            using var ms = new MemoryStream();
            await rawObj.ResponseStream.CopyToAsync(ms);
            var rawBody = ms.ToArray();

            // Upload with random ciphertext (invalid PKCS#1v1.5 padding)
            byte[] randomCiphertext = new byte[_rsa.KeySize / 8];
            RandomNumberGenerator.Fill(randomCiphertext);
            var randomKey = $"{prefix}/random-ciphertext.txt";
            await UploadV1Object(randomKey, rawBody, Convert.ToBase64String(randomCiphertext), iv, matdesc, storageMode);

            // Upload with valid PKCS#1v1.5 ciphertext
            byte[] validCiphertext = _rsa.Encrypt(new byte[32], RSAEncryptionPadding.Pkcs1);
            var validKey = $"{prefix}/valid-ciphertext.txt";
            await UploadV1Object(validKey, rawBody, Convert.ToBase64String(validCiphertext), iv, matdesc, storageMode);

            // Attempt decrypt
            var errorForRandom = await AttemptDecrypt(decryptConfig, isV4, randomKey);
            var errorForValid = await AttemptDecrypt(decryptConfig, isV4, validKey);

            return (errorForRandom, errorForValid);
        }

        private async Task UploadV1Object(string key, byte[] body, string wrappedKeyBase64, string iv, string matdesc,
            CryptoStorageMode storageMode)
        {
            if (storageMode == CryptoStorageMode.InstructionFile)
            {
                await _vanillaS3.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = _bucketName,
                    Key = key,
                    InputStream = new MemoryStream(body)
                });
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
