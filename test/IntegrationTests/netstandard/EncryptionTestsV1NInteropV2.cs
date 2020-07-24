﻿using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.S3;
using Amazon.S3.Model;
using Xunit;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV1NInteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessageV1 = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private const string InstructionAndKMSErrorMessageV2 = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private static readonly string FilePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFile.txt");

        private string bucketName;
        private string kmsKeyID;

        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTestsV1NInteropV2()
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                var response = EncryptionTestsUtils.CallAsyncTask(
                    kmsClient.CreateKeyAsync(new CreateKeyRequest
                    {
                        Description = "Key for .NET integration tests.",
                        Origin = OriginType.AWS_KMS,
                        KeyUsage = KeyUsageType.ENCRYPT_DECRYPT
                    }));
                kmsKeyID = response.KeyMetadata.KeyId;
            }

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterials = new EncryptionMaterials(rsa);
            var symmetricEncryptionMaterials = new EncryptionMaterials(aes);
            var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);
            var config = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(asymmetricEncryptionMaterials);
            s3EncryptionClientFileModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(config, asymmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeSymmetricWrapV1N = new AmazonS3EncryptionClient(symmetricEncryptionMaterials);
            s3EncryptionClientFileModeSymmetricWrapV1N = new AmazonS3EncryptionClient(config, symmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeKMSV1N = new AmazonS3EncryptionClient(kmsEncryptionMaterials);
            s3EncryptionClientFileModeKMSV1N = new AmazonS3EncryptionClient(config, kmsEncryptionMaterials);

            s3EncryptionClientMetadataModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(asymmetricEncryptionMaterials);
            s3EncryptionClientFileModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(config, asymmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(symmetricEncryptionMaterials);
            s3EncryptionClientFileModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(config, symmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(kmsEncryptionMaterials);
            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(config, kmsEncryptionMaterials);

            using (var writer = File.CreateText(FilePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, GetType().Name));
        }

        protected override void Dispose(bool disposing)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                EncryptionTestsUtils.CallAsyncTask(
                    kmsClient.ScheduleKeyDeletionAsync(new ScheduleKeyDeletionRequest
                    {
                        KeyId = kmsKeyID,
                        PendingWindowInDays = 7
                    }));
            }

            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeKMSV1N.Dispose();
            s3EncryptionClientFileModeKMSV1N.Dispose();

            s3EncryptionClientMetadataModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeKMSV2.Dispose();
            s3EncryptionClientFileModeKMSV2.Dispose();
            
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    FilePath, null, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    FilePath, null, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV1);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV1);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV1);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2, bucketName));
            }, InstructionAndKMSErrorMessageV1);
        }
    }
}
