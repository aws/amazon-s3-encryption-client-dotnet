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
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using Amazon.S3.Util;

using Amazon.Runtime;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Xunit;
using System.Text.RegularExpressions;
using Amazon.Extensions.S3.Encryption.Extensions;
using Amazon.Extensions.S3.Encryption.Tests.Common;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    internal partial class EncryptionTestsUtils
    {
        private const long MegaByteSize = 1048576;

        public static void TestTransferUtility(IAmazonS3 s3EncryptionClient, string bucketName)
        {
            TestTransferUtility(s3EncryptionClient, s3EncryptionClient, bucketName);
        }

        public static void TestTransferUtility(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var directory = TransferUtilityTests.CreateTestDirectory(30 * MegaByteSize);
            var keyPrefix = directory.Name;
            var directoryPath = directory.FullName;

            using (var transferUtility = new TransferUtility(s3EncryptionClient))
            {
                var uploadRequest = CreateUploadDirRequest(directoryPath, keyPrefix, bucketName);
                transferUtility.UploadDirectory(uploadRequest);

                var newDir = TransferUtilityTests.GenerateDirectoryPath();
                transferUtility.DownloadDirectory(bucketName, keyPrefix, newDir);
                TransferUtilityTests.ValidateDirectoryContents(s3DecryptionClient, bucketName, keyPrefix, directory);
            }
        }

        public static void TestTransferUtilityCalculateMD5(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var directory = TransferUtilityTests.CreateTestDirectory(10 * TransferUtilityTests.KILO_SIZE);
            var keyPrefix = directory.Name;
            var directoryPath = directory.FullName;

            using (var transferUtility = new TransferUtility(s3EncryptionClient))
            {
                var uploadRequest = CreateUploadDirRequest(directoryPath, keyPrefix, bucketName);
                transferUtility.UploadDirectory(uploadRequest);

                var newDir = TransferUtilityTests.GenerateDirectoryPath();
                transferUtility.DownloadDirectory(bucketName, keyPrefix, newDir);
                TransferUtilityTests.ValidateDirectoryContents(s3DecryptionClient, bucketName, keyPrefix, directory);
            }
        }

        private static TransferUtilityUploadDirectoryRequest CreateUploadDirRequest(string directoryPath, string keyPrefix, string bucketName)
        {
            var uploadRequest =
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

        public static void MultipartEncryptionTest(AmazonS3Client s3EncryptionClient, string bucketName, 
            Dictionary<string, string> ecInInitMPU = null, Dictionary<string, string> ecInGetRequest = null)
        {
            MultipartEncryptionTest(s3EncryptionClient, s3EncryptionClient, bucketName, ecInInitMPU, ecInGetRequest);
        }

        public static void MultipartEncryptionTest(AmazonS3Client s3EncryptionClient, IAmazonS3 s3DecryptionClient, 
            string bucketName, Dictionary<string, string> ecInInitMPU = null, Dictionary<string, string> ecInGetRequest = null)
        {
            var guid = Guid.NewGuid();
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{guid}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retrieved-{guid}.txt");
            var totalSize = MegaByteSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            var key = $"key-{guid}";

            Stream inputStream = File.OpenRead(filePath);
            try
            {
                var initRequest = new InitiateMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    StorageClass = S3StorageClass.OneZoneInfrequentAccess,
                    ContentType = "text/html",
                };
                if (ecInInitMPU != null)
                    initRequest.SetEncryptionContext(ecInInitMPU);

                var initResponse = s3EncryptionClient.InitiateMultipartUpload(initRequest);

                // Upload part 1
                var uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 1,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up1Response = s3EncryptionClient.UploadPart(uploadRequest);

                // Upload part 2
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 2,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up2Response = s3EncryptionClient.UploadPart(uploadRequest);

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

                var up3Response = s3EncryptionClient.UploadPart(uploadRequest);

                var listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                var listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.Equal(3, listPartResponse.Parts.Count);
                Assert.Equal(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.Equal(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.Equal(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.Equal(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.Equal(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.Equal(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.Equal(1, listPartResponse.Parts.Count);

                // Complete the response
                var compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                var compResponse = s3EncryptionClient.CompleteMultipartUpload(compRequest);
                Assert.Equal(bucketName, compResponse.BucketName);
                Assert.NotNull(compResponse.ETag);
                Assert.Equal(key, compResponse.Key);
                Assert.NotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                var getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                if (ecInGetRequest != null)
                    getRequest.SetEncryptionContext(ecInGetRequest);

                var getResponse = s3DecryptionClient.GetObject(getRequest);
                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                var metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                var metaDataResponse = s3DecryptionClient.GetObjectMetadata(metaDataRequest);
                Assert.Equal("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                if (File.Exists(retrievedFilepath))
                {
                    File.Delete(retrievedFilepath);
                }
            }
            WaitForAsyncTask(MultipartEncryptionTestAsync(s3EncryptionClient, s3DecryptionClient, bucketName));
        }

        public static void MultipartEncryptionTestCalculateMD5(AmazonS3Client s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
        {
            var guid = Guid.NewGuid();
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{guid}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retrieved-{guid}.txt");
            var totalSize = MegaByteSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            var key = $"key-{guid}";

            Stream inputStream = File.OpenRead(filePath);
            try
            {
                var initRequest = new InitiateMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    StorageClass = S3StorageClass.OneZoneInfrequentAccess,
                    ContentType = "text/html"
                };

                var initResponse = s3EncryptionClient.InitiateMultipartUpload(initRequest);

                // Upload part 1
                var uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 1,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up1Response = s3EncryptionClient.UploadPart(uploadRequest);

                // Upload part 2
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 2,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up2Response = s3EncryptionClient.UploadPart(uploadRequest);

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

                var up3Response = s3EncryptionClient.UploadPart(uploadRequest);

                var listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                var listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.Equal(3, listPartResponse.Parts.Count);
                Assert.Equal(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.Equal(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.Equal(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.Equal(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.Equal(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.Equal(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = s3EncryptionClient.ListParts(listPartRequest);
                Assert.Equal(1, listPartResponse.Parts.Count);

                // Complete the response
                var compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                var compResponse = s3EncryptionClient.CompleteMultipartUpload(compRequest);
                Assert.Equal(bucketName, compResponse.BucketName);
                Assert.NotNull(compResponse.ETag);
                Assert.Equal(key, compResponse.Key);
                Assert.NotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                var getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };

                var getResponse = s3DecryptionClient.GetObject(getRequest);
                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                var metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                var metaDataResponse = s3DecryptionClient.GetObjectMetadata(metaDataRequest);
                Assert.Equal("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                if (File.Exists(retrievedFilepath))
                {
                    File.Delete(retrievedFilepath);
                }
            }
            WaitForAsyncTask(MultipartEncryptionTestAsync(s3EncryptionClient, s3DecryptionClient, bucketName));
        }

        internal static void TestPutGet(IAmazonS3 s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName,
            string key = null, Dictionary<string, string> ecInPutRequest = null, Dictionary<string, string> ecInGetRequest = null)
        {
            TestPutGet(s3EncryptionClient, s3EncryptionClient, filePath, inputStreamBytes, contentBody,
                expectedContent, bucketName, key, ecInPutRequest, ecInGetRequest);
        }

        internal static void TestPutGet(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName,
            string key = null, Dictionary<string, string> ecInPutRequest = null, Dictionary<string, string> ecInGetRequest = null)
        {
            if (key == null)
                key = $"key-{Guid.NewGuid()}";
            
            TestPut(s3EncryptionClient, filePath, inputStreamBytes, contentBody, bucketName, key, ecInPutRequest);
            TestGet(key, expectedContent, s3DecryptionClient, bucketName, ecInGetRequest);

            WaitForAsyncTask(TestPutGetAsync(s3EncryptionClient, filePath, inputStreamBytes, contentBody, expectedContent, bucketName, ecInPutRequest, ecInGetRequest));
        }
        
        internal static void TestPut(IAmazonS3 s3EncryptionClient, string filePath, byte[] inputStreamBytes, 
            string contentBody, string bucketName, string key, Dictionary<string, string> ecInPutRequest = null)
        {
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            if (ecInPutRequest != null)
            {
                request.SetEncryptionContext(ecInPutRequest);
            }

            s3EncryptionClient.PutObject(request);
        }

        internal static void TestPutGetCalculateMD5(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody
            };

            var response = s3EncryptionClient.PutObject(request);
            TestGet(request.Key, expectedContent, s3DecryptionClient, bucketName);

            WaitForAsyncTask(TestPutGetAsync(s3EncryptionClient, filePath, inputStreamBytes, contentBody, expectedContent, bucketName));
        }

        internal static void TestGet(string key, string uploadedData, IAmazonS3 s3Client, string bucketName,
            Dictionary<string, string> requestEC = null, bool validateUploadedData = true, bool validateEC = false, 
            Dictionary<string, string> expectedEC = null)
        {
            var getObjectResponse = MakeGetObjectCall((AmazonS3Client) s3Client, bucketName, key, requestEC);
            if (validateEC)
                CommonUtils.ValidateMaterialDescription(getObjectResponse, expectedEC);
            if (validateUploadedData)
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    var data = reader.ReadToEnd();
                    Assert.Equal(uploadedData, data);
                }
            }
        }
        
        public static void DecryptDataKeyWithoutS3EC(string key, AmazonS3Client s3Client, string bucketName,
            string encryptionDataKeyLocation, Dictionary<string, string> ECToKMS = null, Dictionary<string, string> requestEC = null)
        {
            var getObjectResponse = MakeGetObjectCall(s3Client, bucketName, key, requestEC);
            
            var kmsClient = new AmazonKeyManagementServiceClient();
            var encryptedKey = getObjectResponse.Metadata[encryptionDataKeyLocation];
            var decryptRequest = new DecryptRequest
            {
                CiphertextBlob = new MemoryStream(Convert.FromBase64String(encryptedKey)),
                EncryptionContext = ECToKMS
            };
            
            // Decrypt will fail ECToKMS is incorrect
            kmsClient.Decrypt(decryptRequest);
        }

        public static void TestRangeGetDisabled(IAmazonS3 s3EncryptionClient, string bucketName)
        {
            var getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = "foo",
                ByteRange = new ByteRange(2, 4)
            };

            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClient.GetObject(getObjectRequest);
            }, typeof(NotSupportedException), RangeGetNotSupportedMessage);

            AssertExtensions.ExpectException(() =>
            {
                WaitForAsyncTask(AttemptRangeGetAsync(s3EncryptionClient, getObjectRequest));
            }, typeof(NotSupportedException), RangeGetNotSupportedMessage);
        }

        internal static void WaitForAsyncTask(System.Threading.Tasks.Task asyncTask)
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

        internal static async System.Threading.Tasks.Task MultipartEncryptionTestAsync(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient, 
            string bucketName, Dictionary<string, string> ecInInitMPU = null, Dictionary<string, string> ecInGetRequest = null)
        {
            var guid = Guid.NewGuid();
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{guid}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retrieved-{guid}.txt");
            var totalSize = MegaByteSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            var key = $"key-{guid}";

            Stream inputStream = File.OpenRead(filePath);
            try
            {
                var initRequest = new InitiateMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    StorageClass = S3StorageClass.OneZoneInfrequentAccess,
                    ContentType = "text/html"
                };
                if (ecInInitMPU != null)
                    initRequest.SetEncryptionContext(ecInInitMPU);

                var initResponse =
                    await s3EncryptionClient.InitiateMultipartUploadAsync(initRequest).ConfigureAwait(false);

                // Upload part 1
                var uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 1,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up1Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                // Upload part 2
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 2,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };

                var up2Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

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

                var up3Response = await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                var listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                var listPartResponse = await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
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
                var compRequest = new CompleteMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };
                compRequest.AddPartETags(up1Response, up2Response, up3Response);

                var compResponse =
                    await s3EncryptionClient.CompleteMultipartUploadAsync(compRequest).ConfigureAwait(false);
                Assert.Equal(bucketName, compResponse.BucketName);
                Assert.NotNull(compResponse.ETag);
                Assert.Equal(key, compResponse.Key);
                Assert.NotNull(compResponse.Location);

                // Get the file back from S3 and make sure it is still the same.
                var getRequest = new GetObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                if (ecInGetRequest != null)
                    getRequest.SetEncryptionContext(ecInGetRequest);

                var getResponse =
                    await s3DecryptionClient.GetObjectAsync(getRequest).ConfigureAwait(false);
                getResponse.WriteResponseStreamToFile(retrievedFilepath);

                UtilityMethods.CompareFiles(filePath, retrievedFilepath);

                var metaDataRequest = new GetObjectMetadataRequest()
                {
                    BucketName = bucketName,
                    Key = key
                };
                var metaDataResponse =
                    await s3DecryptionClient.GetObjectMetadataAsync(metaDataRequest).ConfigureAwait(false);
                Assert.Equal("text/html", metaDataResponse.Headers.ContentType);
            }
            finally
            {
                inputStream.Close();
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                if (File.Exists(retrievedFilepath))
                {
                    File.Delete(retrievedFilepath);
                }
            }

        }

        private static async System.Threading.Tasks.Task TestPutGetAsync(IAmazonS3 s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName,
            Dictionary<string, string> ecInPutRequest = null, Dictionary<string, string> ecInGetRequest = null)
        {
            String key = $"key-{Guid.NewGuid()}";

            await TestPutAsync(s3EncryptionClient, filePath, inputStreamBytes, contentBody, bucketName, key,
                ecInPutRequest).ConfigureAwait(false);
            await TestGetAsync(key, expectedContent, s3EncryptionClient, bucketName, ecInGetRequest).ConfigureAwait(false);
        }
        
        internal static async System.Threading.Tasks.Task TestPutAsync(IAmazonS3 s3EncryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string bucketName, string key,
            Dictionary<string, string> ecInPutRequest = null)
        {
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            if (ecInPutRequest != null)
            {
                request.SetEncryptionContext(ecInPutRequest);
            }

            await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
        }

        internal static async System.Threading.Tasks.Task TestGetAsync(string key, string uploadedData, 
            IAmazonS3 s3EncryptionClient, string bucketName, Dictionary<string, string> ecInGetRequest = null, 
            bool validateUploadedData = true, bool validateEC = false, Dictionary<string, string> expectedEC = null)
        {
            var getObjectResponse = await CommonUtils.MakeGetObjectAsyncCall((AmazonS3Client) s3EncryptionClient, 
                bucketName, key, ecInGetRequest).ConfigureAwait(false);
            if (validateEC)
                CommonUtils.ValidateMaterialDescription(getObjectResponse, expectedEC);
            if (validateUploadedData)
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    var data = reader.ReadToEnd();
                    Assert.Equal(uploadedData, data);
                }
            }
        }
        
        public static GetObjectResponse MakeGetObjectCall(AmazonS3Client s3Client, string bucketName, string key, 
            Dictionary<string, string> requestEC = null)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };
            if (requestEC != null)
            {
                getObjectRequest.SetEncryptionContext(requestEC);
            }
            
            var getObjectResponse = s3Client.GetObject(getObjectRequest);
            
            return getObjectResponse;
        }

        public static async System.Threading.Tasks.Task AttemptRangeGetAsync(IAmazonS3 s3EncryptionClient, GetObjectRequest getObjectRequest)
        {
            await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false);
        }
    }
}