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
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Amazon.S3;
using Amazon.S3.Encryption;
using Amazon.S3.Util;

using Amazon.Runtime;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    [TestClass]
    public partial class EncryptionTestsV2
    {
        private const string InstructionAndKMSErrorMessage = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string sampleContent = "Encryption Client V2 Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);
        private static readonly string filePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFileV2.txt");

        private static string bucketName;
        private static string kmsKeyID;
        
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataMode;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileMode;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMS;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMS;

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

            var encryptionMaterials = new EncryptionMaterials(new RSACryptoServiceProvider());
            var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);

            AmazonS3CryptoConfiguration config = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataMode = new AmazonS3EncryptionClientV2(encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataMode);

            s3EncryptionClientFileMode = new AmazonS3EncryptionClientV2(config, encryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileMode);

            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClientV2(kmsEncryptionMaterials);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMS);

            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClientV2(config, kmsEncryptionMaterials);
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
            Directory.Delete(TransferUtilityTests.BasePath, true);
            if (File.Exists(filePath))
                File.Delete(filePath);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientFileMode()
        {
            EncryptionTests.TestTransferUtility(s3EncryptionClientFileMode, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataMode()
        {
            EncryptionTests.TestTransferUtility(s3EncryptionClientMetadataMode, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTests.TestTransferUtility(s3EncryptionClientFileModeKMS, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTests.TestTransferUtility(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingMetadataMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataMode, filePath, null, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingInstructionFileMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientFileMode, filePath, null, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingMetadataMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataMode, null, sampleContentBytes, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingInstructionFileMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientFileMode, null, sampleContentBytes, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingMetadataMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataMode, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetZeroLengthContentUsingMetadataMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataMode, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetNullContentContentUsingMetadataMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataMode, null, null, null, 
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingInstructionFileMode()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientFileMode, null, null, sampleContent,
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }
        [TestMethod]
        [TestCategory("S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTests.TestPutGet(s3EncryptionClientFileModeKMS, filePath, null, null, 
                    null, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes, null, 
                null, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTests.TestPutGet(s3EncryptionClientFileModeKMS, null, sampleContentBytes, null, 
                    null, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, sampleContent, 
                S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, "", 
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTests.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, null,
                S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTests.TestPutGet(s3EncryptionClientFileModeKMS, null, null, sampleContent, 
                    S3CannedACL.AuthenticatedRead, sampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestMetadataMode()
        {
            EncryptionTests.MultipartEncryptionTest(s3EncryptionClientMetadataMode, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestInstructionFile()
        {
            EncryptionTests.MultipartEncryptionTest(s3EncryptionClientFileMode, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            EncryptionTests.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [TestMethod]
        [TestCategory("S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTests.MultipartEncryptionTest(s3EncryptionClientFileModeKMS, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

#if AWS_APM_API

        private static readonly Regex APMKMSErrorRegex = new Regex("Please use the synchronous version instead.");

        [TestMethod]
        public void TestGetObjectAPMKMS()
        {
            var random = new Random();
            PutObjectRequest putObjectRequest = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
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
        }

        [TestMethod]
        public void TestPutObjectAPMKMS()
        {
            var random = new Random();
            PutObjectRequest request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                ContentBody = sampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMS.EndPutObject(
                    s3EncryptionClientMetadataModeKMS.BeginPutObject(request, null, null));
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
        }

#endif
    }
}
