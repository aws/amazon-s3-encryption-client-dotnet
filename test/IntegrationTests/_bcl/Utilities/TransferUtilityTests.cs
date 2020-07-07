using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Amazon.S3Encryption.IntegrationTests
{
    public class TransferUtilityTests
    {
        public static readonly long MEG_SIZE = (int)Math.Pow(2, 20);
        public static readonly long KILO_SIZE = (int)Math.Pow(2, 10);
        public static readonly string BasePath = @"c:\temp\test\transferutility\";
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

        public static void ValidateFileContents(IAmazonS3 s3client, string bucketName, string key, string path)
        {
            // test assumes we used a known extension and added it to the file key
            var ext = Path.GetExtension(key);
            ValidateFileContents(s3client, bucketName, key, path, AmazonS3Util.MimeTypeFromExtension(ext));
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
                        Assert.AreEqual(contentType, response.Headers.ContentType);
                    }
                    response.WriteResponseStreamToFile(downloadPath);
                }
                return true;
            }, sleepSeconds: 2, maxWaitSeconds: 10);
            UtilityMethods.CompareFiles(path, downloadPath);
        }
    }
}
