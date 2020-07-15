using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Xunit;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;
using InitiateMultipartUploadRequest = Amazon.Extensions.S3.Encryption.Model.InitiateMultipartUploadRequest;

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

        private AmazonS3EncryptionClient s3EncryptionClientMetadataMode;
        private AmazonS3EncryptionClient s3EncryptionClientFileMode;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMS;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeKMS;
        
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeV2;
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

            var encryptionMaterials = new EncryptionMaterials(RSA.Create());
            var kmsEncryptionMaterialsV1 = new EncryptionMaterials(kmsKeyID);
            
            var kmsEncryptionMaterialsV2 = new EncryptionMaterials(kmsKeyID);

            AmazonS3CryptoConfiguration config = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataMode = new AmazonS3EncryptionClient(encryptionMaterials);
            s3EncryptionClientFileMode = new AmazonS3EncryptionClient(config, encryptionMaterials);
            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClient(kmsEncryptionMaterialsV1);
            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClient(config, kmsEncryptionMaterialsV1);
            
            s3EncryptionClientMetadataModeV2 = new AmazonS3EncryptionClientV2(encryptionMaterials);
            s3EncryptionClientFileModeV2 = new AmazonS3EncryptionClientV2(config, encryptionMaterials);
            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(kmsEncryptionMaterialsV2);
            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(config, kmsEncryptionMaterialsV2);

            using (StreamWriter writer = File.CreateText(filePath))
            {
                writer.Write(sampleContent);
            }
            bucketName = CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileMode, GetType().Name));
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
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataMode, bucketName));
            s3EncryptionClientMetadataMode.Dispose();
            s3EncryptionClientFileMode.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            
            s3EncryptionClientFileModeKMS.Dispose();
            s3EncryptionClientMetadataModeV2.Dispose();
            s3EncryptionClientFileModeV2.Dispose();
            s3EncryptionClientMetadataModeKMSV2.Dispose();
            s3EncryptionClientFileModeKMSV2.Dispose();
            
            if (File.Exists(filePath))
                File.Delete(filePath);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataMode()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataMode, 
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
            
            await TestPutGetAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, 
                filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileMode()
        {
            await TestPutGetAsync(s3EncryptionClientFileMode, 
                filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2,
                    filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataMode()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataMode,
                null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileMode()
        {
            await TestPutGetAsync(s3EncryptionClientFileMode,
                null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2,
                    null, sampleContentBytes, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataMode()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataMode, null, null, 
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2,
                null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataMode()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataMode, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
            
            await TestPutGetAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, 
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataMode()
        {
            await TestPutGetAsync(s3EncryptionClientMetadataMode, null, null, null, 
                S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, 
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileMode()
        {
            await TestPutGetAsync(s3EncryptionClientFileMode, null, null, sampleContent,
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            await TestPutGetAsync(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2,
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
        public async void MultipartEncryptionTestMetadataMode()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataMode, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFile()
        {
            await MultipartEncryptionTestAsync(s3EncryptionClientFileMode, bucketName).ConfigureAwait(false);

            await MultipartEncryptionTestAsync(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2, bucketName)
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
            var filePath = $@"C:\temp\multi-{nextRandom}.txt";
            var retrievedFilepath = $@"C:\temp\retreived-{nextRandom}.txt";
            var totalSize = MegSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            string key = $"key-{random.Next()}";

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
