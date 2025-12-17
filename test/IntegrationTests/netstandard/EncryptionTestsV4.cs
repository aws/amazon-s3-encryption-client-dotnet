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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using Amazon.S3.Model;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV4 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage =
            "AmazonS3EncryptionClientV4 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string KeyCommitmentMismatchErrorMessage =
            "Stored key commitment does not match the derived key commitment value";

        private const string sampleContent = "Encryption Client Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);

        private string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private string bucketName;
        private string kmsKeyID;
        private RSA rsa;
        private Aes aes;

        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrap;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrap;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrap;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrap;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMS;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMS;

        private AmazonS3Client vanillaS3Client;
        
        private IEnumerable<AmazonS3EncryptionClientV4> AllWorkingS3ecClients => [
            s3EncryptionClientMetadataModeAsymmetricWrap,
            s3EncryptionClientFileModeAsymmetricWrap,
            s3EncryptionClientMetadataModeSymmetricWrap,
            s3EncryptionClientFileModeSymmetricWrap,
            s3EncryptionClientMetadataModeKMS
        ];
        
        public static IEnumerable<object[]> GetAllWorkingS3ecClients() => 
            Enumerable.Range(0, 5).Select(i => new object[] { i });

        public EncryptionTestsV4(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsIdAsync().GetAwaiter().GetResult();

            rsa = RSA.Create();
            aes = Aes.Create();

            var asymmetricEncryptionMaterials = new EncryptionMaterialsV4(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterials = new EncryptionMaterialsV4(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterials =
                new EncryptionMaterialsV4(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            var fileConfig = new AmazonS3CryptoConfigurationV4
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            
            var metadataConfig = new AmazonS3CryptoConfigurationV4
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };

            s3EncryptionClientMetadataModeAsymmetricWrap =
                new AmazonS3EncryptionClientV4(metadataConfig, asymmetricEncryptionMaterials);
            s3EncryptionClientFileModeAsymmetricWrap =
                new AmazonS3EncryptionClientV4(fileConfig, asymmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeSymmetricWrap =
                new AmazonS3EncryptionClientV4(metadataConfig, symmetricEncryptionMaterials);
            s3EncryptionClientFileModeSymmetricWrap =
                new AmazonS3EncryptionClientV4(fileConfig, symmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClientV4(metadataConfig, kmsEncryptionMaterials);
            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClientV4(fileConfig, kmsEncryptionMaterials);

            vanillaS3Client = new AmazonS3Client();

            using (var writer = new StreamWriter(File.OpenWrite(filePath)))
            {
                writer.Write(sampleContent);
                writer.Flush();
            }

            bucketName =
                EncryptionTestsUtils.CallAsyncTask(
                    UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrap));
        }

        protected override void Dispose(bool disposing)
        {
            EncryptionTestsUtils.CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();
            vanillaS3Client.Dispose();
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null,
                null,
                sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null,
                    sampleContent, bucketName, key)
                .ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa, true);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null,
                    sampleContent, bucketName, key)
                .ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa, true);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Theory]
        [MemberData(nameof(GetAllWorkingS3ecClients))]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetTamperedEncryptionContentUsingMetadataMode(int clientIndex)
        {
            var client = AllWorkingS3ecClients.ElementAt(clientIndex);
            // Put encrypted content
            var key = await PutContentAsync(client, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        
            // Tamper the content
            await TamperCipherTextAsync(vanillaS3Client, bucketName, key);
        
            // Verify
            AssertExtensions.ExpectException<AmazonCryptoException>(
                () =>
                {
                    AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                        client, bucketName));
                }, "Failed to decrypt: mac check in GCM failed");
        }

        [Theory]
        [MemberData(nameof(GetAllWorkingS3ecClients))]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetTamperedCekAlgUsingMetadataMode(int clientIndex)
        {
            var client = AllWorkingS3ecClients.ElementAt(clientIndex);
            // Put encrypted content
            var key = await PutContentAsync(client, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Tamper the cek algorithm
            await TamperCekAlgAsync(vanillaS3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException<InvalidDataException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                    client, bucketName));
            });
        }

        [Theory]
        [MemberData(nameof(GetAllWorkingS3ecClients))]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetTamperedKeyCommitmentUsingMetadataMode(int clientIndex)
        {
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
            var client = AllWorkingS3ecClients.ElementAt(clientIndex);
            // Put encrypted content
            var key = await PutContentAsync(client, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Tamper the key commitment
            await TamperKeyCommitmentAsync(vanillaS3Client, bucketName, key);
            
            // Verify S3EC fails
            AssertExtensions.ExpectException<AmazonCryptoException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                    client, bucketName));
            }, KeyCommitmentMismatchErrorMessage);
        }

        [Fact]
        public async Task PutGetReplacedEncryptedKeyUsingMetadataMode()
        {
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
            
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeKMS, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Replace encrypted key with AES 256 key from KMS GDK
            await ReplaceEncryptedKeyAsync(vanillaS3Client, bucketName, key, kmsKeyID);

            // Verify S3EC fails
            AssertExtensions.ExpectException<AmazonCryptoException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                    s3EncryptionClientMetadataModeKMS, bucketName));
            }, KeyCommitmentMismatchErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                "", "", bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                "", "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                null, "", bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa, true);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName, key).ConfigureAwait(false);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS,
                    filePath, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS,
                    null, sampleContentBytes, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentWithTamperedEncryptionContextUsingMetadataModeKMS()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeKMS, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Tamper the encryption context
            await TamperEncryptionContextAsync(vanillaS3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException<InvalidCiphertextException>(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeKMS,
                        bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                "", "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS, null,
                    null, sampleContent, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}"; 
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap,
                bucketName, key);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingInstructionFileAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap,
                bucketName, key);
            await EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
            await EncryptionTestsUtils.ValidateRsaEnvelopeKeyFormat(vanillaS3Client, key, bucketName, rsa, true);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEnecryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    AsyncHelpers.RunSync(() =>
                        EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMS, bucketName));
                }, InstructionAndKMSErrorMessage);
        }

        public static async Task<string> PutContentAsync(AmazonS3Client s3EncryptionClient, string filePath,
            byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            var key = $"key-{Guid.NewGuid()}";
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            var response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            return key;
        }

        private static async Task TamperCipherTextAsync(AmazonS3Client s3Client, string bucketName, string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();

                // Flip the stored cipher text first byte and put back
                data[0] = (byte)~data[0];
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TamperCekAlgAsync(AmazonS3Client s3Client, string bucketName, string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-c"))
                    {
                        putObjectRequest.Metadata.Add(metadataKey, "Unsupported");
                    }
                    else
                    {
                        putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                    }
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TamperEncryptionContextAsync(AmazonS3Client s3Client, string bucketName,
            string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data)
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-t"))
                    {
                        putObjectRequest.Metadata.Add("x-amz-meta-x-amz-t", "{\"Hello\":\"World\"}");
                        continue;
                    }

                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TamperKeyCommitmentAsync(AmazonS3Client s3Client, string bucketName, string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data)
                };
                
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-d"))
                    {
                        var keyCommitmentBase64 = getObjectResponse.Metadata[metadataKey];
                        var keyCommitmentBytes = Convert.FromBase64String(keyCommitmentBase64);
                        keyCommitmentBytes[0] ^= 1; // Flip first bit
                        putObjectRequest.Metadata.Add(metadataKey, Convert.ToBase64String(keyCommitmentBytes));
                    }
                    else
                    {
                        putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                    }
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task ReplaceEncryptedKeyAsync(AmazonS3Client s3Client, string bucketName, string key, string kmsKeyId)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data)
                };
                
                // Generate random AES 256 key (32 bytes) and encrypt with KMS
                
                using (var kmsClient = new Amazon.KeyManagementService.AmazonKeyManagementServiceClient())
                {
                    var generateDataKeyWithoutPlaintextResponse = await kmsClient.GenerateDataKeyAsync(
                        new GenerateDataKeyRequest()
                        {
                            KeyId = kmsKeyId,
                            NumberOfBytes = 32,
                            EncryptionContext =
                                new Dictionary<string, string> { ["aws:x-amz-cek-alg"] = "115" }
                        });
                    
                    foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                    {
                        if (metadataKey.Equals("x-amz-meta-x-amz-3"))
                        {
                            putObjectRequest.Metadata.Add(metadataKey, Convert.ToBase64String(generateDataKeyWithoutPlaintextResponse.CiphertextBlob.ToArray()));
                        }
                        else
                        {
                            putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                        }
                    }
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }
    }
}