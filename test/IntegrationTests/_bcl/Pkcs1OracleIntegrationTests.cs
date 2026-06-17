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
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3;
using Amazon.S3.Model;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.S3.Util;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    /// <summary>
    /// Integration tests verifying that security profiles which forbid legacy reads
    /// reject V1 metadata BEFORE performing the RSA private key operation.
    /// </summary>
    public class Pkcs1OracleIntegrationTests : TestBase<AmazonS3Client>
    {
        private readonly RSA _rsa = RSA.Create(2048);
        private readonly AmazonS3Client _vanillaS3 = new AmazonS3Client();
        private readonly string _bucketName;

        public Pkcs1OracleIntegrationTests() : base(KmsKeyIdProvider.Instance)
        {
            _bucketName = S3TestUtils.CreateBucketWithWait(_vanillaS3);
        }

        protected override void Dispose(bool disposing)
        {
            AmazonS3Util.DeleteS3BucketWithObjects(_vanillaS3, _bucketName);
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
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV2(SecurityProfile.V2,
                    CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
                { StorageMode = CryptoStorageMode.ObjectMetadata });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // V4 + ForbidEncryptAllowDecrypt + AesGcm
        // Must reject V1 metadata before RSA decrypt — no oracle
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_ForbidEncryptAllowDecrypt_AesGcm_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
                { StorageMode = CryptoStorageMode.ObjectMetadata });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // V4 + RequireEncryptAllowDecrypt + AesGcmWithCommitment
        // Must reject V1 metadata before RSA decrypt — no oracle
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptAllowDecrypt_AesGcmWithCommitment_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
                { StorageMode = CryptoStorageMode.ObjectMetadata });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // V4 + RequireEncryptRequireDecrypt + AesGcmWithCommitment
        // Commitment check fires before unwrap
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptRequireDecrypt_AesGcmWithCommitment_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
                { StorageMode = CryptoStorageMode.ObjectMetadata });

            Assert.IsType<ArgumentException>(result.Item1);
            Assert.IsType<ArgumentException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("The requested object is encrypted with non key committing algorithm", result.Item1.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Instruction File variants
        // ═══════════════════════════════════════════════════════════════════
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V2_ForbidEncryptAllowDecrypt_AesGcm_InstructionFile_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV2(SecurityProfile.V2,
                    CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
                { StorageMode = CryptoStorageMode.InstructionFile });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_ForbidEncryptAllowDecrypt_AesGcm_InstructionFile_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
                { StorageMode = CryptoStorageMode.InstructionFile });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptAllowDecrypt_AesGcmWithCommitment_InstructionFile_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
                { StorageMode = CryptoStorageMode.InstructionFile });

            Assert.IsType<AmazonCryptoException>(result.Item1);
            Assert.IsType<AmazonCryptoException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("V1 encryption schemas that have been disabled", result.Item1.Message);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task V4_RequireEncryptRequireDecrypt_AesGcmWithCommitment_InstructionFile_NoOracle()
        {
            var result = await RunOracleTest(
                new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                    CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
                { StorageMode = CryptoStorageMode.InstructionFile });

            Assert.IsType<ArgumentException>(result.Item1);
            Assert.IsType<ArgumentException>(result.Item2);
            Assert.Equal(result.Item1.Message, result.Item2.Message);
            Assert.Contains("The requested object is encrypted with non key committing algorithm", result.Item1.Message);
        }

        // ═══════════════════════════════════════════════════════════════════

        private async Task<Tuple<Exception, Exception>> RunOracleTest(AmazonS3CryptoConfigurationBase decryptConfig)
        {
            var prefix = string.Format("pkcs1-oracle/{0}", Guid.NewGuid().ToString("N"));
            var isV4 = decryptConfig is AmazonS3CryptoConfigurationV4;
            var storageMode = decryptConfig.StorageMode;

            // Encrypt with V2 (RSA-OAEP) — the oracle test targets the decryption path, so the encrypting client doesn't matter. 
            var originalKey = prefix + "/original.txt";
            var encConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            { StorageMode = storageMode };
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
                var instrFileResp = await _vanillaS3.GetObjectAsync(_bucketName, originalKey + ".instruction");
                string instrContent;
                using (var reader = new StreamReader(instrFileResp.ResponseStream))
                {
                    instrContent = await reader.ReadToEndAsync();
                }
                var instrDict = JsonUtils.ToDictionary(instrContent);
                iv = instrDict["x-amz-iv"];
                matdesc = instrDict.ContainsKey("x-amz-matdesc") ? instrDict["x-amz-matdesc"] : "{}";
            }
            else
            {
                var meta = await _vanillaS3.GetObjectMetadataAsync(_bucketName, originalKey);
                iv = meta.Metadata["x-amz-iv"];
                matdesc = meta.Metadata["x-amz-matdesc"] ?? "{}";
            }

            byte[] rawBody;
            var rawObj = await _vanillaS3.GetObjectAsync(_bucketName, originalKey);
            using (var ms = new MemoryStream())
            {
                await rawObj.ResponseStream.CopyToAsync(ms);
                rawBody = ms.ToArray();
            }

            // Upload with random ciphertext (invalid PKCS#1v1.5 padding)
            byte[] randomCiphertext = new byte[_rsa.KeySize / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomCiphertext);
            }
            var randomKey = prefix + "/random-ciphertext.txt";
            await UploadV1Object(randomKey, rawBody, Convert.ToBase64String(randomCiphertext), iv, matdesc, storageMode);

            // Upload with valid PKCS#1v1.5 ciphertext
            byte[] validCiphertext = _rsa.Encrypt(new byte[32], RSAEncryptionPadding.Pkcs1);
            var validKey = prefix + "/valid-ciphertext.txt";
            await UploadV1Object(validKey, rawBody, Convert.ToBase64String(validCiphertext), iv, matdesc, storageMode);

            // Attempt decrypt
            var errorForRandom = await AttemptDecrypt(decryptConfig, isV4, randomKey);
            var errorForValid = await AttemptDecrypt(decryptConfig, isV4, validKey);

            Assert.NotNull(errorForRandom);
            Assert.NotNull(errorForValid);
            return Tuple.Create(errorForRandom, errorForValid);
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
                    ContentBody = JsonUtils.ToJson(instrDict)
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
                    using (var client = new AmazonS3EncryptionClientV4((AmazonS3CryptoConfigurationV4)config, materials))
                    {
                        var resp = await client.GetObjectAsync(_bucketName, key);
                        using (var reader = new StreamReader(resp.ResponseStream))
                        {
                            await reader.ReadToEndAsync();
                        }
                    }
                }
                else
                {
                    var materials = new EncryptionMaterialsV2(_rsa, AsymmetricAlgorithmType.RsaOaepSha1);
                    using (var client = new AmazonS3EncryptionClientV2((AmazonS3CryptoConfigurationV2)config, materials))
                    {
                        var resp = await client.GetObjectAsync(_bucketName, key);
                        using (var reader = new StreamReader(resp.ResponseStream))
                        {
                            await reader.ReadToEndAsync();
                        }
                    }
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
