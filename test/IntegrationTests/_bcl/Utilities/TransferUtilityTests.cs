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

using Amazon.S3;
using Amazon.S3.Model;
using System;
using System.IO;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public class TransferUtilityTests
    {
        public static readonly long MEG_SIZE = (int)Math.Pow(2, 20);
        public static readonly long KILO_SIZE = (int)Math.Pow(2, 10);
        public static readonly string BasePath = Path.Combine(Path.GetTempPath(), "test", "transferutility");

        public static DirectoryInfo CreateTestDirectory(long size = 0)
        {
            if (size == 0)
                size = 1 * MEG_SIZE;

            var directoryPath = GenerateDirectoryPath();
            for (int i = 0; i < 5; i++)
            {
                var filePath = Path.Combine(Path.Combine(directoryPath, i.ToString()), "file.txt");
                UtilityMethods.GenerateFile(filePath, size);
            }

            return new DirectoryInfo(directoryPath);
        }

        public static string GenerateDirectoryPath(string baseName = "DirectoryTest")
        {
            var directoryName = UtilityMethods.GenerateName(baseName);
            var directoryPath = Path.Combine(BasePath, directoryName);
            return directoryPath;
        }

        public static void ValidateDirectoryContents(IAmazonS3 s3client, string bucketName, string keyPrefix, DirectoryInfo sourceDirectory)
        {
            ValidateDirectoryContents(s3client, bucketName, keyPrefix, sourceDirectory, null);
        }

        public static void ValidateDirectoryContents(IAmazonS3 s3client, string bucketName, string keyPrefix, DirectoryInfo sourceDirectory, string contentType)
        {
            var directoryPath = sourceDirectory.FullName;
            var files = sourceDirectory.GetFiles("*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                var filePath = file.FullName;
                var key = filePath.Substring(directoryPath.Length + 1);
                key = keyPrefix + "/" + key.Replace("\\", "/");
                ValidateFileContents(s3client, bucketName, key, filePath, contentType);
            }
        }

        public static void ValidateFileContents(IAmazonS3 s3client, string bucketName, string key, string path, string contentType)
        {
            var downloadPath = path + ".chk";
            var request = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key,
            };

            UtilityMethods.WaitUntil(() =>
            {
                using (var response = s3client.GetObject(request))
                {
                    if (!string.IsNullOrEmpty(contentType))
                    {
                        Assert.Equal(contentType, response.Headers.ContentType);
                    }
                    response.WriteResponseStreamToFile(downloadPath);
                }
                return true;
            }, sleepSeconds: 2, maxWaitSeconds: 10);
            UtilityMethods.CompareFiles(path, downloadPath);
        }
    }
}
