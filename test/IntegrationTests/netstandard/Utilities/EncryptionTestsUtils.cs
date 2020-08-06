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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    internal partial class EncryptionTestsUtils
    {
        private const long MegaBytesSize = 1048576;

        public static async Task MultipartEncryptionTestAsync(AmazonS3Client s3EncryptionClient, string bucketName)
        {
            await MultipartEncryptionTestAsync(s3EncryptionClient, s3EncryptionClient, bucketName);
        }

        public static async Task MultipartEncryptionTestAsync(AmazonS3Client s3EncryptionClient,
            AmazonS3Client s3DecryptionClient, string bucketName)
        {
            var filePath = Path.GetTempFileName();
            var retrievedFilepath = Path.GetTempFileName();
            var totalSize = MegaBytesSize * 15;

            UtilityMethods.GenerateFile(filePath, totalSize);
            var key = Guid.NewGuid().ToString();

            Stream inputStream = File.OpenRead(filePath);
            try
            {
                InitiateMultipartUploadRequest initRequest = new InitiateMultipartUploadRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    StorageClass = S3StorageClass.OneZoneInfrequentAccess,
                    ContentType = "text/html",
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
                    PartSize = 5 * MegaBytesSize,
                    InputStream = inputStream,
                };

                UploadPartResponse up1Response =
                    await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                // Upload part 2
                uploadRequest = new UploadPartRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId,
                    PartNumber = 2,
                    PartSize = 5 * MegaBytesSize,
                    InputStream = inputStream
                };

                UploadPartResponse up2Response =
                    await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

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

                UploadPartResponse up3Response =
                    await s3EncryptionClient.UploadPartAsync(uploadRequest).ConfigureAwait(false);

                ListPartsRequest listPartRequest = new ListPartsRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    UploadId = initResponse.UploadId
                };

                ListPartsResponse listPartResponse =
                    await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
                Assert.Equal(3, listPartResponse.Parts.Count);
                Assert.Equal(up1Response.PartNumber, listPartResponse.Parts[0].PartNumber);
                Assert.Equal(up1Response.ETag, listPartResponse.Parts[0].ETag);
                Assert.Equal(up2Response.PartNumber, listPartResponse.Parts[1].PartNumber);
                Assert.Equal(up2Response.ETag, listPartResponse.Parts[1].ETag);
                Assert.Equal(up3Response.PartNumber, listPartResponse.Parts[2].PartNumber);
                Assert.Equal(up3Response.ETag, listPartResponse.Parts[2].ETag);

                listPartRequest.MaxParts = 1;
                listPartResponse = await s3EncryptionClient.ListPartsAsync(listPartRequest).ConfigureAwait(false);
                Assert.Single(listPartResponse.Parts);

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

                GetObjectResponse getResponse =
                    await s3DecryptionClient.GetObjectAsync(getRequest).ConfigureAwait(false);
                await getResponse.WriteResponseStreamToFileAsync(retrievedFilepath, false, CancellationToken.None);

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
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            await TestPutGetAsync(s3EncryptionClient, s3EncryptionClient, filePath, inputStreamBytes, contentBody,
                expectedContent, bucketName);
        }

        public static async Task TestPutGetAsync(AmazonS3Client s3EncryptionClient, AmazonS3Client s3DecryptionClient,
            string filePath, byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            PutObjectRequest request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
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

            using (GetObjectResponse getObjectResponse =
                await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                using (var stream = getObjectResponse.ResponseStream)
                using (var reader = new StreamReader(stream))
                {
                    string data = reader.ReadToEnd();
                    Assert.Equal(uploadedData, data);
                }
            }
        }

        public static async Task AttemptRangeGet(IAmazonS3 s3EncryptionClient, string bucketName)
        {
            var getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = "foo",
                ByteRange = new ByteRange(2, 4)
            };

            await s3EncryptionClient.GetObjectAsync(getObjectRequest).ConfigureAwait(false);
        }

        public static void CallAsyncTask(Task asyncTask)
        {
            asyncTask.GetAwaiter().GetResult();
        }

        public static T CallAsyncTask<T>(Task<T> asyncTask)
        {
            return asyncTask.GetAwaiter().GetResult();
        }
    }
}