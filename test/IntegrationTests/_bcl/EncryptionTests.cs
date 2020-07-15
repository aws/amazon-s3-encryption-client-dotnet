using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Model;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using Amazon.S3.Util;

using Amazon.Runtime;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using InitiateMultipartUploadRequest = Amazon.Extensions.S3.Encryption.Model.InitiateMultipartUploadRequest;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    [TestClass]
    public partial class EncryptionTests
    {
        private const string InstructionAndKMSErrorMessage = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const long MegSize = 1048576;
        private const string sampleContent = "Encryption Client Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);
        private static readonly string filePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFile.txt");

        private static string bucketName;
        private static string kmsKeyID;
        
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataMode;
        private static AmazonS3EncryptionClient s3EncryptionClientFileMode;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMS;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeKMS;

        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        [ClassInitialize]
        public static void Initialize(TestContext a)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                var response = kmsClient.CreateKey(new CreateKeyRequest
                {
                    Description = "Key for .NET integration tests.",
                    Origin = OriginType.AWS_KMS,
                    KeyUsage = KeyUsageType.ENCRYPT_DECRYPT
                });
                kmsKeyID = response.KeyMetadata.KeyId;
            }

            var encryptionMaterials = new EncryptionMaterials(RSA.Create());
            var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);

            AmazonS3CryptoConfiguration config = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataMode = new AmazonS3EncryptionClient(encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataMode);

            s3EncryptionClientFileMode = new AmazonS3EncryptionClient(config, encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileMode);

            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClient(kmsEncryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMS);

            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClient(config, kmsEncryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeKMS);

            s3EncryptionClientMetadataModeV2 = new AmazonS3EncryptionClientV2(encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataMode);

            s3EncryptionClientFileModeV2 = new AmazonS3EncryptionClientV2(config, encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileMode);

            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(kmsEncryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMS);

            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(config, kmsEncryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeKMS);

            using (StreamWriter writer = File.CreateText(filePath))
            {
                writer.Write(sampleContent);
            }
            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileMode);
        }

        [ClassCleanup]
        public static void Cleanup()
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                kmsClient.ScheduleKeyDeletion(new ScheduleKeyDeletionRequest
                {
                    KeyId = kmsKeyID,
                    PendingWindowInDays = 7
                });
            }
            AmazonS3Util.DeleteS3BucketWithObjects(s3EncryptionClientMetadataMode, bucketName);
            s3EncryptionClientMetadataMode.Dispose();
            s3EncryptionClientFileMode.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();
            
            s3EncryptionClientMetadataModeV2.Dispose();
            s3EncryptionClientFileModeV2.Dispose();
            s3EncryptionClientMetadataModeKMSV2.Dispose();
            s3EncryptionClientFileModeKMSV2.Dispose();

            Directory.Delete(TransferUtilityTests.BasePath, true);
            if (File.Exists(filePath))
                File.Delete(filePath);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientFileMode()
        {
            TestTransferUtility(s3EncryptionClientFileMode, bucketName);

            TestTransferUtility(s3EncryptionClientFileMode,  s3EncryptionClientFileModeV2, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataMode()
        {
            TestTransferUtility(s3EncryptionClientMetadataMode, bucketName);

            TestTransferUtility(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                TestTransferUtility(s3EncryptionClientFileModeKMS, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                TestTransferUtility(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            TestTransferUtility(s3EncryptionClientMetadataModeKMS, bucketName);

            TestTransferUtility(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, bucketName);
        }

        public static void TestTransferUtility(IAmazonS3 s3EncryptionClient, string bucketName)
        {
            TestTransferUtility(s3EncryptionClient, s3EncryptionClient, bucketName);
        }

        public static void TestTransferUtility(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var directory = TransferUtilityTests.CreateTestDirectory(10 * TransferUtilityTests.KILO_SIZE);
            var keyPrefix = directory.Name;
            var directoryPath = directory.FullName;

            using (var transferUtility = new Amazon.S3.Transfer.TransferUtility(s3EncryptionClient))
            {
                TransferUtilityUploadDirectoryRequest uploadRequest = CreateUploadDirRequest(directoryPath, keyPrefix, bucketName);
                transferUtility.UploadDirectory(uploadRequest);

                var newDir = TransferUtilityTests.GenerateDirectoryPath();
                transferUtility.DownloadDirectory(bucketName, keyPrefix, newDir);
                TransferUtilityTests.ValidateDirectoryContents(s3DecryptionClient, bucketName, keyPrefix, directory);
            }
        }

        private static TransferUtilityUploadDirectoryRequest CreateUploadDirRequest(string directoryPath, string keyPrefix, string bucketName)
        {
            TransferUtilityUploadDirectoryRequest uploadRequest =
                new TransferUtilityUploadDirectoryRequest
                {
                    BucketName = bucketName,
                    Directory = directoryPath,
                    KeyPrefix = keyPrefix,
                    ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256,
                    SearchOption = SearchOption.AllDirectories,
                    SearchPattern = "*"
                };
            return uploadRequest;
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingMetadataMode()
        {
            TestPutGet(s3EncryptionClientMetadataMode, filePath, null, null, null, 
                sampleContent, bucketName);
            
            TestPutGet(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, filePath, null, 
                null, null, sampleContent, bucketName);

        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingInstructionFileMode()
        {
            TestPutGet(s3EncryptionClientFileMode, filePath, null, null, null, sampleContent, bucketName);
            
            TestPutGet(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2, filePath, null, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingMetadataMode()
        {
            TestPutGet(s3EncryptionClientMetadataMode, null, sampleContentBytes, null, null, sampleContent, bucketName);
            
            TestPutGet(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, null, sampleContentBytes, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingInstructionFileMode()
        {
            TestPutGet(s3EncryptionClientFileMode, null, sampleContentBytes, null, null, sampleContent, bucketName);

            TestPutGet(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2, null, sampleContentBytes, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingMetadataMode()
        {
            TestPutGet(s3EncryptionClientMetadataMode, null, null, sampleContent, S3CannedACL.AuthenticatedRead, 
                sampleContent, bucketName);

            TestPutGet(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetZeroLengthContentUsingMetadataMode()
        {
            TestPutGet(s3EncryptionClientMetadataMode, null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
            
            TestPutGet(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetNullContentContentUsingMetadataMode()
        {
            TestPutGet(s3EncryptionClientMetadataMode, null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);

            TestPutGet(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, null, null, null, 
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingInstructionFileMode()
        {
            TestPutGet(s3EncryptionClientFileMode, null, null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName);

            TestPutGet(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }
        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, filePath, null, null, null, 
                    sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, filePath, null, 
                    null, null, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            TestPutGet(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes, null, null, 
                sampleContent, bucketName);
            
            TestPutGet(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, null, 
                sampleContentBytes, null, null, sampleContent, bucketName);

        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, null, sampleContentBytes, null, null,
                    sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, null, sampleContentBytes, 
                    null, null, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
            
            TestPutGet(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, null, 
                null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName);
            
            TestPutGet(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, null, 
                null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
         
            TestPutGet(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, null,
                null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, null, null, sampleContent,
                    S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                TestPutGet(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, null, null, 
                    sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestMetadataMode()
        {
            MultipartEncryptionTest(s3EncryptionClientMetadataMode, bucketName);
            
            MultipartEncryptionTest(s3EncryptionClientMetadataMode, s3EncryptionClientMetadataModeV2, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestInstructionFile()
        {
            MultipartEncryptionTest(s3EncryptionClientFileMode, bucketName);
            
            MultipartEncryptionTest(s3EncryptionClientFileMode, s3EncryptionClientFileModeV2, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            MultipartEncryptionTest(s3EncryptionClientMetadataModeKMS, bucketName);
            
            MultipartEncryptionTest(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMSV2, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                MultipartEncryptionTest(s3EncryptionClientFileModeKMS, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                MultipartEncryptionTest(s3EncryptionClientFileModeKMS, s3EncryptionClientFileModeKMSV2, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        public static void MultipartEncryptionTest(AmazonS3EncryptionClientBase s3EncryptionClient, string bucketName)
        {
            MultipartEncryptionTest(s3EncryptionClient, s3EncryptionClient, bucketName);
        }

        public static void MultipartEncryptionTest(AmazonS3EncryptionClientBase s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var random = new Random();
            var nextRandom = random.Next();
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{nextRandom}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retreived-{nextRandom}.txt");
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

                InitiateMultipartUploadResponse initResponse = s3EncryptionClient.InitiateMultipartUpload(initRequest);

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

                UploadPartResponse up1Response = s3EncryptionClient.UploadPart(uploadRequest);

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

                UploadPartResponse up2Response = s3EncryptionClient.UploadPart(uploadRequest);

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

                UploadPartResponse up3Response = s3EncryptionClient.UploadPart(uploadRequest);

                ListPartsRequest listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                ListPartsResponse listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.AreEqual(3, listPartResponse.Parts.Count);
                Assert.AreEqual(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.AreEqual(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.AreEqual(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.AreEqual(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.AreEqual(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.AreEqual(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.AreEqual(1, listPartResponse.Parts.Count);

                // Complete the response
                CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                CompleteMultipartUploadResponse compResponse = s3EncryptionClient.CompleteMultipartUpload(compRequest);
                Assert.AreEqual(bucketName, compResponse.BucketName);
                Assert.IsNotNull(compResponse.ETag);
                Assert.AreEqual(key, compResponse.Key);
                Assert.IsNotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                GetObjectRequest getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };

                GetObjectResponse getResponse = s3DecryptionClient.GetObject(getRequest);
                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                GetObjectMetadataRequest metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                GetObjectMetadataResponse metaDataResponse = s3DecryptionClient.GetObjectMetadata(metaDataRequest);
                Assert.AreEqual("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                    File.Delete(filePath);
                if (File.Exists(retrievedFilepath))
                    File.Delete(retrievedFilepath);
            }
#if ASYNC_AWAIT
            // run the async version of the same test
            WaitForAsyncTask(MultipartEncryptionTestAsync(s3EncryptionClient, s3DecryptionClient, bucketName));
#elif AWS_APM_API
            // run the APM version of the same test
            MultipartEncryptionTestAPM(s3EncryptionClient, s3DecryptionClient, bucketName);
#endif
        }

        internal static void TestPutGet(IAmazonS3 s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
        {
            TestPutGet(s3EncryptionClient, s3EncryptionClient, filePath, inputStreamBytes, contentBody, cannedACL,
                expectedContent, bucketName);
        }

        internal static void TestPutGet(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
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

            PutObjectResponse response = s3EncryptionClient.PutObject(request);
            TestGet(request.Key, expectedContent, s3DecryptionClient, bucketName);

#if ASYNC_AWAIT
            // run the async version of the same test
            WaitForAsyncTask(TestPutGetAsync(s3EncryptionClient, filePath, inputStreamBytes, contentBody, cannedACL, expectedContent, bucketName));
#elif AWS_APM_API
            // Run the APM version of the same test
            // KMS isn't supported for PutObject and GetObject in the APM.
            if (!IsKMSEncryptionClient(s3EncryptionClient))
                TestPutGetAPM(s3EncryptionClient, s3DecryptionClient, filePath, inputStreamBytes, contentBody, cannedACL, expectedContent, bucketName);
#endif
        }

        private static void TestGet(string key, string uploadedData, IAmazonS3 s3EncryptionClient, string bucketName)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            using (GetObjectResponse getObjectResponse = s3EncryptionClient.GetObject(getObjectRequest))
            using (var stream = getObjectResponse.ResponseStream)
            using (var reader = new StreamReader(stream))
            {
                string data = reader.ReadToEnd();
                Assert.AreEqual(uploadedData, data);
            }
        }

#if ASYNC_AWAIT

        private static void WaitForAsyncTask(System.Threading.Tasks.Task asyncTask)
        {
            try
            {
                asyncTask.Wait();
            }
            catch (AggregateException e)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw();
            }
        }

        private static async System.Threading.Tasks.Task MultipartEncryptionTestAsync(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var random = new Random();
            var nextRandom = random.Next();
            var filePath = $@"C:\temp\multi-{nextRandom}.txt";
            var retrievedFilepath = $@"C:\temp\retreived-{nextRandom}.txt";
            var totalSize = MegSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            string key = "key-" + random.Next();

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
                Assert.AreEqual(3, listPartResponse.Parts.Count);
                Assert.AreEqual(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.AreEqual(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.AreEqual(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.AreEqual(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.AreEqual(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.AreEqual(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
                Assert.AreEqual(1, listPartResponse.Parts.Count);

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
                Assert.AreEqual(bucketName, compResponse.BucketName);
                Assert.IsNotNull(compResponse.ETag);
                Assert.AreEqual(key, compResponse.Key);
                Assert.IsNotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                GetObjectRequest getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };

                GetObjectResponse getResponse =
                    await s3DecryptionClient.GetObjectAsync(getRequest).ConfigureAwait(false);
                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                GetObjectMetadataRequest metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                GetObjectMetadataResponse metaDataResponse =
                    await s3DecryptionClient.GetObjectMetadataAsync(metaDataRequest).ConfigureAwait(false);
                Assert.AreEqual("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                    File.Delete(filePath);
                if (File.Exists(retrievedFilepath))
                    File.Delete(retrievedFilepath);
            }

        }

        private async static System.Threading.Tasks.Task TestPutGetAsync(IAmazonS3 s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
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
            await TestGetAsync(request.Key, expectedContent, s3EncryptionClient, bucketName).ConfigureAwait(false);
        }

        private async static System.Threading.Tasks.Task TestGetAsync(string key, string uploadedData, IAmazonS3 s3EncryptionClient, string bucketName)
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
                    Assert.AreEqual(uploadedData, data);
                }
            }
        }

#elif AWS_APM_API

        private static readonly Regex APMKMSErrorRegex = new Regex("Please use the synchronous version instead.");

        [TestMethod]
        public void TestGetObjectAPMKMS()
        {
            var random = new Random();
            PutObjectRequest putObjectRequest = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key{random.Next()}",
                ContentBody = sampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };
            s3EncryptionClientMetadataModeKMS.PutObject(putObjectRequest);

            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = putObjectRequest.Key
            };

            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMS.EndGetObject(
                    s3EncryptionClientMetadataModeKMS.BeginGetObject(getObjectRequest, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV2.EndGetObject(
                    s3EncryptionClientMetadataModeKMSV2.BeginGetObject(getObjectRequest, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        [TestMethod]
        public void TestPutObjectAPMKMS()
        {
            var random = new Random();
            
            // Request object is modified internally, therefore, it is required to have separate requests for every test
            PutObjectRequest requestV1 = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                ContentBody = sampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMS.EndPutObject(
                    s3EncryptionClientMetadataModeKMS.BeginPutObject(requestV1, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            PutObjectRequest requestV2 = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                ContentBody = sampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMSV2.EndPutObject(
                    s3EncryptionClientMetadataModeKMSV2.BeginPutObject(requestV2, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        [TestMethod]
        public void TestInitiateMultipartUploadAPMKMS()
        {
            var random = new Random();
            InitiateMultipartUploadRequest request = new InitiateMultipartUploadRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                StorageClass = S3StorageClass.ReducedRedundancy,
                ContentType = "text/html",
                CannedACL = S3CannedACL.PublicRead
            };

            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMS.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMS.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV2.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMSV2.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        public static void MultipartEncryptionTestAPM(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
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

                InitiateMultipartUploadResponse initResponse = null;
                if (IsKMSEncryptionClient(s3EncryptionClient))
                    initResponse = s3EncryptionClient.InitiateMultipartUpload(initRequest);
                else
                    initResponse = s3EncryptionClient.EndInitiateMultipartUpload(
                            s3EncryptionClient.BeginInitiateMultipartUpload(initRequest, null, null));

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

                UploadPartResponse up1Response = s3EncryptionClient.EndUploadPart(
                    s3EncryptionClient.BeginUploadPart(uploadRequest, null, null));

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

                UploadPartResponse up2Response = s3EncryptionClient.EndUploadPart(
                    s3EncryptionClient.BeginUploadPart(uploadRequest, null, null));

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

                UploadPartResponse up3Response = s3EncryptionClient.EndUploadPart(
                    s3EncryptionClient.BeginUploadPart(uploadRequest, null, null));

                ListPartsRequest listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                ListPartsResponse listPartResponse = s3EncryptionClient.EndListParts(
                    s3EncryptionClient.BeginListParts(listPartRequest, null, null));
                Assert.AreEqual(3, listPartResponse.Parts.Count);
                Assert.AreEqual(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.AreEqual(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.AreEqual(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.AreEqual(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.AreEqual(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.AreEqual(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = s3EncryptionClient.EndListParts(
                    s3EncryptionClient.BeginListParts(listPartRequest, null, null));
                Assert.AreEqual(1, listPartResponse.Parts.Count);

                // Complete the response
                CompleteMultipartUploadRequest compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                CompleteMultipartUploadResponse compResponse = s3EncryptionClient.EndCompleteMultipartUpload(
                    s3EncryptionClient.BeginCompleteMultipartUpload(compRequest, null, null));

                Assert.AreEqual(bucketName, compResponse.BucketName);
                Assert.IsNotNull(compResponse.ETag);
                Assert.AreEqual(key, compResponse.Key);
                Assert.IsNotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                GetObjectRequest getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };

                GetObjectResponse getResponse = null;
                if (IsKMSEncryptionClient(s3EncryptionClient))
                    getResponse = s3DecryptionClient.GetObject(getRequest);
                else
                    getResponse = s3DecryptionClient.EndGetObject(
                        s3DecryptionClient.BeginGetObject(getRequest, null, null));

                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                GetObjectMetadataRequest metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                GetObjectMetadataResponse metaDataResponse = s3DecryptionClient.EndGetObjectMetadata(
                    s3DecryptionClient.BeginGetObjectMetadata(metaDataRequest, null, null));
                Assert.AreEqual("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                    File.Delete(filePath);
                if (File.Exists(retrievedFilepath))
                    File.Delete(retrievedFilepath);
            }
        }

        internal static bool IsKMSEncryptionClient(IAmazonS3 s3EncryptionClient)
        {
            var encryptionMaterials = ReflectionHelpers.Invoke(s3EncryptionClient, "EncryptionMaterials");
            var kmsKeyID = ReflectionHelpers.Invoke(encryptionMaterials, "KMSKeyID");
            return kmsKeyID != null;
        }

        private static void TestPutGetAPM(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
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
            PutObjectResponse response = s3EncryptionClient.EndPutObject(s3EncryptionClient.BeginPutObject(request, null, null));
            TestGetAPM(request.Key, expectedContent, s3DecryptionClient, bucketName);
        }

        private static void TestGetAPM(string key, string uploadedData, IAmazonS3 s3EncryptionClient, string bucketName)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            var asyncResult = s3EncryptionClient.BeginGetObject(getObjectRequest, null, null);
            using (GetObjectResponse getObjectResponse = s3EncryptionClient.EndGetObject(asyncResult))
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    string data = reader.ReadToEnd();
                    Assert.AreEqual(uploadedData, data);
                }
            }
        }

#endif
    }
}
