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

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{

    public partial class EncryptionTestsV1InteropV1N : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                             "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private static readonly string FilePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFile.txt");

        private static string bucketName;
        private static string kmsKeyID;
        
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1;
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1;
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1;
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1;
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1;
        private static Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1;

        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;

        public EncryptionTestsV1InteropV1N()
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

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(rsa);
            var asymmetricEncryptionMaterialsV1N = new EncryptionMaterials(rsa);

            var symmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(aes);
            var symmetricEncryptionMaterialsV1N = new EncryptionMaterials(aes);

            var kmsEncryptionMaterialsV1 = new  Amazon.S3.Encryption.EncryptionMaterials(kmsKeyID);
            var kmsEncryptionMaterialsV1N = new EncryptionMaterials(kmsKeyID);

            var configV1 = new Amazon.S3.Encryption.AmazonS3CryptoConfiguration()
            {
                StorageMode = Amazon.S3.Encryption.CryptoStorageMode.InstructionFile
            };
            var configV1N = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeAsymmetricWrapV1);

            s3EncryptionClientFileModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, asymmetricEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeAsymmetricWrapV1);

            s3EncryptionClientMetadataModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeSymmetricWrapV1);

            s3EncryptionClientFileModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, symmetricEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeSymmetricWrapV1);

            s3EncryptionClientMetadataModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(kmsEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMSV1);

            s3EncryptionClientFileModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, kmsEncryptionMaterialsV1);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeKMSV1);

            s3EncryptionClientMetadataModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeAsymmetricWrapV1N);

            s3EncryptionClientFileModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, asymmetricEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeAsymmetricWrapV1N);

            s3EncryptionClientMetadataModeSymmetricWrapV1N = new AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeSymmetricWrapV1N);

            s3EncryptionClientFileModeSymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, symmetricEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeSymmetricWrapV1N);

            s3EncryptionClientMetadataModeKMSV1N = new AmazonS3EncryptionClient(kmsEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMSV1N);

            s3EncryptionClientFileModeKMSV1N = new AmazonS3EncryptionClient(configV1N, kmsEncryptionMaterialsV1N);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeKMSV1N);

            using (var writer = File.CreateText(FilePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileModeAsymmetricWrapV1);
        }
        protected override void Dispose(bool disposing)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                kmsClient.ScheduleKeyDeletion(new ScheduleKeyDeletionRequest
                {
                    KeyId = kmsKeyID,
                    PendingWindowInDays = 7
                });
            }
            AmazonS3Util.DeleteS3BucketWithObjects(s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName);
            s3EncryptionClientMetadataModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeKMSV1.Dispose();
            s3EncryptionClientFileModeKMSV1.Dispose();
            
            s3EncryptionClientMetadataModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeKMSV1N.Dispose();
            s3EncryptionClientFileModeKMSV1N.Dispose();

            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV1,  s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV1,  s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                FilePath, null, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                FilePath, null, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                FilePath, null, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                FilePath, null, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                FilePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    FilePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    FilePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    null, SampleContentBytes, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N, null,
                null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
         
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName);
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV1, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV1, bucketName);
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV1, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV1, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV1N, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV1, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV1N, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

#if AWS_APM_API

        private static readonly Regex APMKMSErrorRegex = new Regex("Please use the synchronous version instead.");

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestGetObjectAPMKMS()
        {
            var random = new Random();
            PutObjectRequest putObjectRequest = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key{random.Next()}",
                ContentBody = SampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };
            s3EncryptionClientMetadataModeKMSV1.PutObject(putObjectRequest);

            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = putObjectRequest.Key
            };

            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV1.EndGetObject(
                    s3EncryptionClientMetadataModeKMSV1.BeginGetObject(getObjectRequest, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV1N.EndGetObject(
                    s3EncryptionClientMetadataModeKMSV1N.BeginGetObject(getObjectRequest, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestPutObjectAPMKMS()
        {
            var random = new Random();
            
            // Request object is modified internally, therefore, it is required to have separate requests for every test
            PutObjectRequest requestV1 = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                ContentBody = SampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMSV1.EndPutObject(
                    s3EncryptionClientMetadataModeKMSV1.BeginPutObject(requestV1, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            PutObjectRequest requestV2 = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{random.Next()}",
                ContentBody = SampleContent,
                CannedACL = S3CannedACL.AuthenticatedRead
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMSV1N.EndPutObject(
                    s3EncryptionClientMetadataModeKMSV1N.BeginPutObject(requestV2, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
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
                s3EncryptionClientMetadataModeKMSV1.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMSV1.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV1N.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMSV1N.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }
#endif
    }
}
