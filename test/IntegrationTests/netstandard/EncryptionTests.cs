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
    public class EncryptionTests : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const long MegSize = 1048576;
        private const string sampleContent = "Encryption Client Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);
        private static readonly string filePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFile.txt");

        private string bucketName;
        private string kmsKeyID;

        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrap;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrap;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrap;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrap;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMS;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeKMS;
        
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTests()
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                var response = CallAsyncTask(
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
            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterials(rsa);

            var symmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(aes);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterials(aes);

            var kmsEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(kmsKeyID);
            var kmsEncryptionMaterialsV2 = new EncryptionMaterials(kmsKeyID);

            var configV1 = new Amazon.S3.Encryption.AmazonS3CryptoConfiguration()
            {
                StorageMode = Amazon.S3.Encryption.CryptoStorageMode.InstructionFile
            };
            var configV2 = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataModeAsymmetricWrap = new Amazon.S3.Encryption.AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeAsymmetricWrap = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, asymmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeSymmetricWrap = new Amazon.S3.Encryption.AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeSymmetricWrap = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, symmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeKMS = new Amazon.S3.Encryption.AmazonS3EncryptionClient(kmsEncryptionMaterialsV1);
            s3EncryptionClientFileModeKMS = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, kmsEncryptionMaterialsV1);

            s3EncryptionClientMetadataModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(asymmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(configV2, asymmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(symmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(configV2, symmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(kmsEncryptionMaterialsV2);
            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(configV2, kmsEncryptionMaterialsV2);

            using (StreamWriter writer = File.CreateText(filePath))
            {
                writer.Write(sampleContent);
            }
            bucketName = CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrap, GetType().Name));
        }

        protected override void Dispose(bool disposing)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                CallAsyncTask(
                    kmsClient.ScheduleKeyDeletionAsync(new ScheduleKeyDeletionRequest
                    {
                        KeyId = kmsKeyID,
                        PendingWindowInDays = 7
                    }));
            }

            CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();

            s3EncryptionClientMetadataModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeKMSV2.Dispose();
            s3EncryptionClientFileModeKMSV2.Dispose();
            
            if (File.Exists(filePath))
                File.Delete(filePath);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
            
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap,
                filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, s3EncryptionClientFileModeSymmetricWrapV2,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap,
                null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap,
                null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }


        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, "",
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
            
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null, "",
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, null,
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null, null,
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, null, sampleContent,
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, null, sampleContent,
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, filePath, 
                    null, null, null, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, null, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes, null, 
                null, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2,
                null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, null, 
                    sampleContentBytes, null, null, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2,
                null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, null, 
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, null, 
                    null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return TestPutGetAsync(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2,
                    null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName); });
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap, s3EncryptionClientFileModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMS, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMS, bucketName); });
            }, InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, bucketName); });
            }, InstructionAndKMSErrorMessage);
        }

        public static async Task MultipartEncryptionTestAsync(AmazonS3Client s3EncryptionClient,
            string bucketName)
        {
            await MultipartEncryptionTestAsync(s3EncryptionClient, s3EncryptionClient, bucketName);
        }

        public static async Task MultipartEncryptionTestAsync(AmazonS3Client s3EncryptionClient, AmazonS3Client s3DecryptionClient, string bucketName)
        {
            var random = new Random();
            var nextRandom = random.Next();
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{nextRandom}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retreived-{nextRandom}.txt");
            var totalSize = MegSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            string key = $"key-{nextRandom}";

            Stream inputStream = File.OpenRead(filePath);
            try
            {
                InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    StorageClass = S3StorageClass.ReducedRedundancy,
                    ContentType = "text/html",
                    CannedACL = S3CannedACL.PublicRead
                };

                InitiateMultipartUploadResponse initResponse =
                    await s3EncryptionClient.InitiateMultipartUploadAsync(initRequest).ConfigureAwait(false);

                // Upload part 1
                UploadPartRequest uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 1,
                    PartSize = 5 * MegSize,
                    InputStream = inputStream,
                };

                UploadPartResponse up1Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                // Upload part 2
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 2,
                    PartSize = 5 * MegSize,
                    InputStream = inputStream,
                };

                UploadPartResponse up2Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                // Upload part 3
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 3,
                    InputStream = inputStream,
                    IsLastPart = true
                };

                UploadPartResponse up3Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                ListPartsRequest listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                ListPartsResponse listPartResponse = await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
                Assert.Equal(3, listPartResponse.Parts.Count);
                Assert.Equal(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.Equal(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.Equal(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.Equal(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.Equal(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.Equal(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
                Assert.Equal(1, listPartResponse.Parts.Count);

                // Complete the response
                CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                CompleteMultipartUploadResponse compResponse =
                    await s3EncryptionClient.CompleteMultipartUploadAsync(compRequest).ConfigureAwait(false);
                Assert.Equal(bucketName, compResponse.BucketName);
                Assert.NotNull(compResponse.ETag);
                Assert.Equal(key, compResponse.Key);
                Assert.NotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                GetObjectRequest getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };

                GetObjectResponse getResponse = await s3DecryptionClient.GetObjectAsync(getRequest).ConfigureAwait(false);
                await getResponse.WriteResponseStreamToFileAsync(retrievedFilepath, false, System.Threading.CancellationToken.None);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                GetObjectMetadataRequest metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                GetObjectMetadataResponse metaDataResponse =
                    await s3DecryptionClient.GetObjectMetadataAsync(metaDataRequest).ConfigureAwait(false);
                Assert.Equal("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Dispose();
                if (File.Exists(filePath))
                    File.Delete(filePath);
                if (File.Exists(retrievedFilepath))
                    File.Delete(retrievedFilepath);
            }

        }
        
        public static async Task TestPutGetAsync(AmazonS3Client s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent,
            string bucketName)
        {
            await TestPutGetAsync(s3EncryptionClient, s3EncryptionClient, filePath, inputStreamBytes, contentBody,
                cannedACL, expectedContent, bucketName);
        }

        public static async Task TestPutGetAsync(AmazonS3Client s3EncryptionClient, AmazonS3Client s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent,
            string bucketName)
        {
            var random = new Random();

            PutObjectRequest request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
                CannedACL = cannedACL
            };
            PutObjectResponse response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            await TestGetAsync(request.Key, expectedContent, s3DecryptionClient, bucketName).ConfigureAwait(false);
        }

        public static async Task TestGetAsync(string key, string uploadedData, AmazonS3Client s3EncryptionClient,
            string bucketName)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            using (GetObjectResponse getObjectResponse = await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    string data = reader.ReadToEnd();
                    Assert.Equal(uploadedData, data);
                }
            }
        }

        public static void CallAsyncTask(Task asyncTask)
        {
            try
            {
                asyncTask.Wait();
            }
            catch (AggregateException e)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw();
                // shouldn't happen but makes the compiler happy
                throw;
            }
        }

        public static T CallAsyncTask<T>(Task<T> asyncTask)
        {
            try
            {
                asyncTask.Wait();
                return asyncTask.Result;
            }
            catch (AggregateException e)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw();
                // shouldn't happen but makes the compiler happy
                throw;
            }
        }
    }
}
