using Amazon.S3;
using Amazon.S3.Util;
using Amazon.S3.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using Amazon.Runtime.Internal;
using Amazon.Runtime;
using System.IO;
using System.Reflection;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;

using System.Security.Cryptography;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    internal class UtilityMethods
    {
        public const string SDK_TEST_PREFIX = "aws-net-sdk";

        public async static Task<string> CreateBucketAsync(IAmazonS3 s3Client, string testName)
        {
            string bucketName = string.Format("{0}-{1}-{2}", UtilityMethods.SDK_TEST_PREFIX, testName, DateTime.Now.Ticks).ToLower().Replace('_', '-');
            await s3Client.PutBucketAsync(new PutBucketRequest { BucketName = bucketName }).ConfigureAwait(false);
            return bucketName;
        }

        public static void WriteFile(string path, string contents)
        {
            string fullPath = Path.GetFullPath(path);
            new DirectoryInfo(Path.GetDirectoryName(fullPath)).Create();
            File.WriteAllText(fullPath, contents);
        }

        public static void GenerateFile(string path, long size)
        {
            string contents = GenerateTestContents(size);
            WriteFile(path, contents);
        }

        public static string GenerateTestContents(long size)
        {
            StringBuilder sb = new StringBuilder();
            for (long i = 0; i < size; i++)
            {
                char c = (char)('a' + (i % 26));
                sb.Append(c);
            }
            string contents = sb.ToString();
            return contents;
        }

        public static Task DeleteBucketWithObjectsAsync(IAmazonS3 s3Client, string bucketName)
        {
            return DeleteS3BucketWithObjectsAsync(s3Client, bucketName);
        }

        private async static Task DeleteS3BucketWithObjectsAsync(IAmazonS3 s3Client, string bucketName,
            CancellationToken cancellationToken = new CancellationToken())
        {
            // Validations.
            if (s3Client == null)
            {
                throw new ArgumentNullException("s3Client", "The s3Client cannot be null!");
            }

            if (string.IsNullOrEmpty(bucketName))
            {
                throw new ArgumentNullException("bucketName", "The bucketName cannot be null or empty string!");
            }

            var listVersionsRequest = new ListVersionsRequest
            {
                BucketName = bucketName
            };

            ListVersionsResponse listVersionsResponse;
            string lastRequestId = null;

            // Iterate through the objects in the bucket and delete them.
            do
            {
                // Check if the operation has been canceled.
                cancellationToken.ThrowIfCancellationRequested();

                // List all the versions of all the objects in the bucket.
                listVersionsResponse = await s3Client.ListVersionsAsync(listVersionsRequest).ConfigureAwait(false);

                // Silverlight uses HTTP caching, so avoid an infinite loop by throwing an exception
                if (string.Equals(lastRequestId, listVersionsResponse.ResponseMetadata.RequestId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException();
                }
                lastRequestId = listVersionsResponse.ResponseMetadata.RequestId;

                if (listVersionsResponse.Versions.Count == 0)
                {
                    // If the bucket has no objects break the loop.
                    break;
                }

                var keyVersionList = new List<KeyVersion>(listVersionsResponse.Versions.Count);
                for (int index = 0; index < listVersionsResponse.Versions.Count; index++)
                {
                    keyVersionList.Add(new KeyVersion
                    {
                        Key = listVersionsResponse.Versions[index].Key,
                        VersionId = listVersionsResponse.Versions[index].VersionId
                    });
                }

                try
                {
                    // Delete the current set of objects.
                    var deleteObjectsResponse = await s3Client.DeleteObjectsAsync(new DeleteObjectsRequest
                    {
                        BucketName = bucketName,
                        Objects = keyVersionList,
                        Quiet = true
                    }).ConfigureAwait(false);

                    //if (!deleteOptions.QuietMode)
                    //{
                    //    // If quiet mode is not set, update the client with list of deleted objects.
                    //    InvokeS3DeleteBucketWithObjectsUpdateCallback(
                    //                    updateCallback,
                    //                    new S3DeleteBucketWithObjectsUpdate
                    //                    {
                    //                        DeletedObjects = deleteObjectsResponse.DeletedObjects
                    //                    }
                    //                );
                    //}
                }
                catch //(DeleteObjectsException deleteObjectsException)
                {
                    //if (deleteOptions.ContinueOnError)
                    //{
                    //    // Continue the delete operation if an error was encountered.
                    //    // Update the client with the list of objects that were deleted and the 
                    //    // list of objects on which the delete failed.
                    //    InvokeS3DeleteBucketWithObjectsUpdateCallback(
                    //            updateCallback,
                    //            new S3DeleteBucketWithObjectsUpdate
                    //            {
                    //                DeletedObjects = deleteObjectsException.Response.DeletedObjects,
                    //                DeleteErrors = deleteObjectsException.Response.DeleteErrors
                    //            }
                    //        );
                    //}
                    //else
                    //{
                    //    // Re-throw the exception if an error was encountered.
                    //    throw;
                    //}

                    throw;
                }

                // Set the markers to get next set of objects from the bucket.
                listVersionsRequest.KeyMarker = listVersionsResponse.NextKeyMarker;
                listVersionsRequest.VersionIdMarker = listVersionsResponse.NextVersionIdMarker;

            }
            // Continue listing objects and deleting them until the bucket is empty.
            while (listVersionsResponse.IsTruncated);

            const int maxRetries = 10;
            for (int retries = 1; retries <= maxRetries; retries++)
            {
                try
                {
                    // Bucket is empty, delete the bucket.
                    await s3Client.DeleteBucketAsync(new DeleteBucketRequest
                    {
                        BucketName = bucketName
                    }).ConfigureAwait(false);
                    break;
                }
                catch (AmazonS3Exception e)
                {
                    if (e.StatusCode != HttpStatusCode.Conflict || retries == maxRetries)
                        throw;
                    else
                        DefaultRetryPolicy.WaitBeforeRetry(retries, 5000);
                }
            }

            //// Signal that the operation is completed.
            //asyncCancelableResult.SignalWaitHandleOnCompleted();
        }

        public static void RunAsSync(Func<Task> asyncFunc)
        {
            Task.Run(asyncFunc).Wait();
        }


        private static byte[] computeHash(string file)
        {
            byte[] fileMD5;
            using (Stream fileStream = File.OpenRead(file))
            {
                fileMD5 = MD5.Create().ComputeHash(fileStream);
            }
            return fileMD5;
        }

        public static void CompareFiles(string file1, string file2)
        {
            byte[] file1MD5 = computeHash(file1);
            byte[] file2MD5 = computeHash(file2);

            Assert.Equal(file1MD5.Length, file2MD5.Length);
            for (int i = 0; i < file1MD5.Length; i++)
            {
                Assert.Equal(file1MD5[i], file2MD5[i]);
            }
        }

    }
}
