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
using System.Linq;
using System.Text;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;

using Xunit;
using Amazon.Extensions.S3.Encryption.Util;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    internal partial class EncryptionTestsUtils
    {
        private const long MegaByteSize = 1048576;
        
        private static readonly string[] ExpectedContentMetadataV1 =
        {
            "x-amz-unencrypted-content-length",
            "x-amz-key",
            "x-amz-matdesc",
            "x-amz-iv"
        };
        
        private static readonly string[] ExpectedContentMetadataV2S3ECMetaDataMode =
        {
            // Exception: x-amz-unencrypted-content-length is added in V2 metadata too (only in metadata mode)
            "x-amz-unencrypted-content-length",
            "x-amz-key-v2",
            "x-amz-matdesc",
            "x-amz-iv",
            "x-amz-wrap-alg",
            "x-amz-cek-alg"
        };
        
        private static readonly string[] ExpectedContentMetadataV2S3ECInstructionFileMode =
        {
            "x-amz-key-v2",
            "x-amz-matdesc",
            "x-amz-iv",
            "x-amz-wrap-alg",
            "x-amz-cek-alg"
        };
            
        private static readonly string[] ExpectedMetadataV3 =
        {
            "x-amz-c",      
            "x-amz-3",      
            "x-amz-w",      
            "x-amz-d",      
            "x-amz-i",      
            "x-amz-t"
        };
        
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

        public static void MultipartEncryptionTest(AmazonS3Client s3EncryptionClient, string bucketName, string key = null)
        {
            MultipartEncryptionTest(s3EncryptionClient, s3EncryptionClient, bucketName, key);
        }

        public static void MultipartEncryptionTest(AmazonS3Client s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string bucketName, string key = null)
        {
            var guid = Guid.NewGuid();
            if (key == null)
            {
                key = $"key-{guid}";
            }
            var filePath = Path.Combine(Path.GetTempPath(), $"multi-{guid}.txt");
            var retrievedFilepath = Path.Combine(Path.GetTempPath(), $"retrieved-{guid}.txt");
            var totalSize = MegaByteSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);

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
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - CreateMultipartUpload MAY be implemented by the S3EC.
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - If implemented, CreateMultipartUpload MUST initiate a multipart upload.
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
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MAY be implemented by the S3EC.
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MUST encrypt each part.
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
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MAY be implemented by the S3EC.
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MUST encrypt each part.
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
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MAY be implemented by the S3EC.
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - UploadPart MUST encrypt each part.
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
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=test
                //# - CompleteMultipartUpload MAY be implemented by the S3EC.
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
        
        public static void MultipartEncryptionTest_WhenUploadPartIsNotInCorrectSequence(AmazonS3Client s3EncryptionClient, IAmazonS3 s3DecryptionClient, string bucketName)
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

                // Upload part 3
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 3,
                    PartSize = 5 * MegaByteSize,
                    InputStream = inputStream
                };
                
                s3EncryptionClient.UploadPart(uploadRequest);
                
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
                
                // This should throw an exception because part number 2 was uploaded after part number 3.
                s3EncryptionClient.UploadPart(uploadRequest);
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
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName, string key = null)
        {
            TestPutGet(s3EncryptionClient, s3EncryptionClient, filePath, inputStreamBytes, contentBody,
                expectedContent, bucketName, key);
        }
        
        //= ../specification/s3-encryption/client.md#required-api-operations
        //= type=test
        //# - PutObject MUST be implemented by the S3EC.
        internal static void TestPutGet(IAmazonS3 s3EncryptionClient, IAmazonS3 s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName, string key = null)
        {
            if (key == null)
                key = $"key-{Guid.NewGuid()}";
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            
            // This is tested round trip test.
            //= ../specification/s3-encryption/client.md#required-api-operations
            //= type=test
            //# - PutObject MUST encrypt its input data before it is uploaded to S3.
            var response = s3EncryptionClient.PutObject(request);
            TestGet(request.Key, expectedContent, s3DecryptionClient, bucketName);

            WaitForAsyncTask(TestPutGetAsync(s3EncryptionClient, filePath, inputStreamBytes, contentBody, expectedContent, bucketName));
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
        
        //= ../specification/s3-encryption/client.md#required-api-operations
        //= type=test
        //# - GetObject MUST be implemented by the S3EC.
        internal static void TestGet(string key, string uploadedData, IAmazonS3 s3EncryptionClient, string bucketName)
        {
            var getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = s3EncryptionClient.GetObject(getObjectRequest))
            using (var stream = getObjectResponse.ResponseStream)
            using (var reader = new StreamReader(stream))
            {
                var data = reader.ReadToEnd();
                //= ../specification/s3-encryption/client.md#required-api-operations
                //= type=test
                //# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
                Assert.Equal(uploadedData, data);
            }
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
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            var response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            await TestGetAsync(request.Key, expectedContent, s3EncryptionClient, bucketName).ConfigureAwait(false);
        }

        private static async System.Threading.Tasks.Task TestGetAsync(string key, string uploadedData, IAmazonS3 s3EncryptionClient, string bucketName)
        {
            var getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    var data = reader.ReadToEnd();
                    Assert.Equal(uploadedData, data);
                }
            }
        }
        
        internal static void ValidateMetaData(IAmazonS3 s3Client, string key, string bucketName, int expectedFormatVersion)
        {
            var getRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            var response = s3Client.GetObject(getRequest);
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
            // Note: this is also present in V2 in .NET
            
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.

            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
                
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.

            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
                
            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.

            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.

            //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //= type=test
            //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
            
            if (expectedFormatVersion == 1)
            {
                foreach (var metadataKey in ExpectedContentMetadataV1)
                {
                    Assert.NotNull(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedContentMetadataV2S3ECMetaDataMode.Except(ExpectedContentMetadataV1))
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedMetadataV3)
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
            }
            else if (expectedFormatVersion == 2)
            {
                foreach (var metadataKey in ExpectedContentMetadataV2S3ECMetaDataMode)
                {
                    Assert.NotNull(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedContentMetadataV1.Except(ExpectedContentMetadataV2S3ECMetaDataMode))
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedMetadataV3)
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
            }
            else if (expectedFormatVersion == 3)
            {
                Assert.NotNull(response.Metadata["x-amz-w"]);
                var isKms = response.Metadata["x-amz-w"] == "12"; // 12 is kms+context
                foreach (var metadataKey in ExpectedMetadataV3)
                {
                    var shouldBeNull = 
                        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                        //= type=test
                        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
                        (isKms && metadataKey == "x-amz-m") || 
                        //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                        //= type=test
                        //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
                        (!isKms && metadataKey == "x-amz-t");
                    if (shouldBeNull)
                        Assert.Null(response.Metadata[metadataKey]);
                    else
                        Assert.NotNull(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedContentMetadataV2S3ECMetaDataMode)
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
                foreach (var metadataKey in ExpectedContentMetadataV1)
                {
                    Assert.Null(response.Metadata[metadataKey]);
                }
            }
        }
        
        internal static void ValidateInstructionFile(IAmazonS3 s3Client, string key, string bucketName, int expectedFormatVersion)
        {
            var instructionData = GetPairsFromInstructionFile(s3Client, key, bucketName);
            
            // We do not support and validate v1 instruction files
            if (expectedFormatVersion == 2)
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.

                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.

                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.

                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.

                //= ../specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //= type=test
                //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
                foreach (var metadataKey in ExpectedContentMetadataV2S3ECInstructionFileMode)
                {
                    Assert.True(instructionData.ContainsKey(metadataKey), $"Instruction file missing key: {metadataKey}");
                }
            }
            else if (expectedFormatVersion == 3)
            {
                var metadataRequest = new GetObjectRequest { BucketName = bucketName, Key = key };
                var metadataResponse = s3Client.GetObject(metadataRequest);
                    
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
                Assert.True(instructionData.ContainsKey("x-amz-3"), "V3 instruction file missing x-amz-3");
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
                Assert.True(instructionData.ContainsKey("x-amz-w"), "V3 instruction file missing x-amz-w");
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
                Assert.True(instructionData.ContainsKey("x-amz-m"), "V3 instruction file missing x-amz-m for non-KMS");
                
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                // //= type=test
                // //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
                Assert.False(instructionData.ContainsKey("x-amz-c"), "V3 instruction file must not contain x-amz-c");
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
                Assert.False(instructionData.ContainsKey("x-amz-d"), "V3 instruction file must not contain x-amz-d");
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
                Assert.False(instructionData.ContainsKey("x-amz-i"), "V3 instruction file must not contain x-amz-i");
                
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
                Assert.NotNull(metadataResponse.Metadata["x-amz-c"]);
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
                Assert.NotNull(metadataResponse.Metadata["x-amz-d"]);
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
                //= type=test
                //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
                Assert.NotNull(metadataResponse.Metadata["x-amz-i"]);
            } 
            else
            {
                throw new NotSupportedException($"Version {expectedFormatVersion} is not supported or tested");
            }
        }
        
        internal static void ValidateMetaDataIsReturnedAsIs(IAmazonS3 vanillaS3Client, IAmazonS3 s3EncryptionClient, string key, string bucketName, int expectedFormatVersion)
        {
#pragma warning disable 0618
            Assert.True(s3EncryptionClient is AmazonS3EncryptionClientV2 || s3EncryptionClient is AmazonS3EncryptionClientV4);
#pragma warning restore 0618
            Assert.True(expectedFormatVersion >= 1 && expectedFormatVersion <= 3);
            var getRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };

            var vanillaClientResponse = vanillaS3Client.GetObject(getRequest);
            var s3ecClientResponse = s3EncryptionClient.GetObject(getRequest);

            string[] expectedMetaData;
            if (expectedFormatVersion == 1)
            {
                expectedMetaData = ExpectedContentMetadataV1;
            }
            else if (expectedFormatVersion == 2)
            {
                expectedMetaData = ExpectedContentMetadataV2S3ECMetaDataMode;
            }
            else
            {
                expectedMetaData = ExpectedMetadataV3;
            }

            foreach (var metadataKey in expectedMetaData)
            {
                //= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
                //= type=test
                //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
                Assert.Equal(vanillaClientResponse.Metadata[metadataKey], s3ecClientResponse.Metadata[metadataKey]);
            }
        }
        
        internal static void ValidateRsaEnvelopeKeyFormat(IAmazonS3 vanillaS3Client, string key, string bucketName, RSA rsa, bool isInsFileMode = false)
        {
            Dictionary<string, string> instructionData = null;
            if (isInsFileMode)
            {
                instructionData = GetPairsFromInstructionFile(vanillaS3Client, key, bucketName);
                Assert.NotNull(instructionData);
                // v3 stores cek alg in metadata only
                Assert.False(instructionData.ContainsKey("x-amz-c"));
            }
            
            var getRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };
            var response = vanillaS3Client.GetObject(getRequest);
            
            var hasV2Key = isInsFileMode ? instructionData.ContainsKey("x-amz-key-v2") : response.Metadata["x-amz-key-v2"] != null;
            var hasV3Key = isInsFileMode ? instructionData.ContainsKey("x-amz-3") : response.Metadata["x-amz-3"] != null;
            if (!hasV2Key && !hasV3Key)
            {
                throw new NotSupportedException($"{nameof(ValidateRsaEnvelopeKeyFormat)} only tests for v2 and v3 message format. " +
                                                $"object does not contain v2 message format meta data (x-amz-key-v2) or v3 message format meta data (x-amz-c). " +
                                                "v1 message format is not tested because RSA Envelope Key format only contains the RSA key.");
            }

            var (keyField, cekField) = hasV2Key ? ("x-amz-key-v2", "x-amz-cek-alg") : ("x-amz-3", "x-amz-c");

            var encryptedEnvelopeKeyB64 = isInsFileMode ? instructionData[keyField] : response.Metadata[keyField];
            var storedCekAlg = isInsFileMode ? instructionData[cekField] : response.Metadata[cekField];
            
            var encryptedEnvelopeKey = Convert.FromBase64String(encryptedEnvelopeKeyB64);
            var decryptedEnvelopeKey = rsa.Decrypt(encryptedEnvelopeKey, RSAEncryptionPadding.OaepSHA1);
            
            // Validate envelope key format: [1 byte length] + [key] + [CEK algorithm UTF-8]
            var keyLength = (int)decryptedEnvelopeKey[0];
            var dataKey = new byte[keyLength];
            Array.Copy(
                sourceArray: decryptedEnvelopeKey, 
                sourceIndex: 1, 
                destinationArray: dataKey, 
                destinationIndex: 0, 
                length: keyLength);
            
            var cekAlgBytes = new byte[decryptedEnvelopeKey.Length - 1 - keyLength];
            Array.Copy(
                sourceArray: decryptedEnvelopeKey, 
                sourceIndex: 1 + keyLength, 
                destinationArray: cekAlgBytes, 
                destinationIndex: 0, 
                length: cekAlgBytes.Length);
            Array.Copy(decryptedEnvelopeKey, 1 + keyLength, cekAlgBytes, 0, cekAlgBytes.Length);
            var cekAlgorithm = Encoding.UTF8.GetString(cekAlgBytes);
            
            Assert.Equal(32, keyLength); // 256-bit AES key
            Assert.Equal(32, dataKey.Length);
            Assert.Equal(hasV2Key ? "AES/GCM/NoPadding" : "115", cekAlgorithm);
            Assert.Equal(cekAlgorithm, storedCekAlg);
        }

        private static Dictionary<string, string> GetPairsFromInstructionFile(IAmazonS3 vanillaS3Client, string key, string bucketName)
        {
            var instructionFileKey = key + ".instruction";
            var getRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = instructionFileKey
            };

            var response = vanillaS3Client.GetObject(getRequest);
            
            using (var stream = response.ResponseStream)
            using (var reader = new StreamReader(stream))
            {
                var content = reader.ReadToEnd();
                var instructionData = JsonUtils.ToDictionary(content);
                return instructionData;
            }
        }
        
        public static async System.Threading.Tasks.Task AttemptRangeGetAsync(IAmazonS3 s3EncryptionClient, GetObjectRequest getObjectRequest)
        {
            await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false);
        }
    }
}