using System;
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
    public class EncryptionTestsV1InteropV1N : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKmsErrorMessage = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                             "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private static readonly string FilePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFile.txt");

        private string bucketName;
        private string kmsKeyID;

        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1;

        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;

        public EncryptionTestsV1InteropV1N()
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

            var asymmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(rsa);
            var asymmetricEncryptionMaterialsV1N = new EncryptionMaterials(rsa);

            var symmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(aes);
            var symmetricEncryptionMaterialsV1N = new EncryptionMaterials(aes);

            var kmsEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(kmsKeyID);
            var kmsEncryptionMaterialsV1N = new EncryptionMaterials(kmsKeyID);

            var configV1 = new Amazon.S3.Encryption.AmazonS3CryptoConfiguration()
            {
                StorageMode = Amazon.S3.Encryption.CryptoStorageMode.InstructionFile
            };
            var configV1N = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, asymmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, symmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(kmsEncryptionMaterialsV1);
            s3EncryptionClientFileModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, kmsEncryptionMaterialsV1);

            s3EncryptionClientMetadataModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1N);
            s3EncryptionClientFileModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, asymmetricEncryptionMaterialsV1N);
            s3EncryptionClientMetadataModeSymmetricWrapV1N = new AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1N);
            s3EncryptionClientFileModeSymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, symmetricEncryptionMaterialsV1N);
            s3EncryptionClientMetadataModeKMSV1N = new AmazonS3EncryptionClient(kmsEncryptionMaterialsV1N);
            s3EncryptionClientFileModeKMSV1N = new AmazonS3EncryptionClient(configV1N, kmsEncryptionMaterialsV1N);

            using (var writer = File.CreateText(FilePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrapV1, GetType().Name));
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

            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeKMSV1.Dispose();
            s3EncryptionClientFileModeKMSV1.Dispose();

            s3EncryptionClientMetadataModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeKMSV1N.Dispose();
            s3EncryptionClientFileModeKMSV1N.Dispose();
            
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N,s3EncryptionClientMetadataModeAsymmetricWrapV1,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N, 
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                    FilePath, null, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    FilePath, null, null, null, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    FilePath, null, null, null, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    null, SampleContentBytes, null, null, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1, bucketName); });
            }, InstructionAndKmsErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N, bucketName); });
            }, InstructionAndKmsErrorMessage);
        }
    }
}
