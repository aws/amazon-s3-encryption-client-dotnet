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
using Amazon.Extensions.S3.Encryption.Primitives;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{

    public partial class EncryptionTestsV1NInteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessageV1N = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                                "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private const string InstructionAndKMSErrorMessageV2 = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private static readonly string LegacyReadWhenLegacyDisabledMessage = $"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V2)}." +
                                                                             $" Retry with {nameof(SecurityProfile.V2AndLegacy)} enabled or reencrypt the object.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private static string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private static string bucketName;
        private static string kmsKeyID;

        private readonly AmazonS3CryptoConfigurationV2 metadataConfigV2;
        private readonly AmazonS3CryptoConfigurationV2 fileConfigV2;
        
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;

        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTestsV1NInteropV2()
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

            var asymmetricEncryptionMaterialsV1N = new EncryptionMaterials(rsa);
            var symmetricEncryptionMaterialsV1N = new EncryptionMaterials(aes);
            var kmsEncryptionMaterialsV1N = new  EncryptionMaterials(kmsKeyID);
            var configV1N = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV2 = new  EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata,
            };

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

            s3EncryptionClientMetadataModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, asymmetricEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeAsymmetricWrapV2);

            s3EncryptionClientFileModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, asymmetricEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeAsymmetricWrapV2);

            s3EncryptionClientMetadataModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, symmetricEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeSymmetricWrapV2);

            s3EncryptionClientFileModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, symmetricEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeSymmetricWrapV2);

            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientMetadataModeKMSV2);

            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(fileConfigV2, kmsEncryptionMaterialsV2);
            RetryUtilities.ForceConfigureClient(s3EncryptionClientFileModeKMSV2);

            using (var writer = File.CreateText(filePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileModeAsymmetricWrapV1N);
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
            AmazonS3Util.DeleteS3BucketWithObjects(s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);
            s3EncryptionClientMetadataModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1N.Dispose();
            s3EncryptionClientMetadataModeKMSV1N.Dispose();
            s3EncryptionClientFileModeKMSV1N.Dispose();
            
            s3EncryptionClientMetadataModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV2.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV2.Dispose();
            s3EncryptionClientMetadataModeKMSV2.Dispose();
            s3EncryptionClientFileModeKMSV2.Dispose();

            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV1N,  s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV1N,  s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                filePath, null, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                filePath, null, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                filePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                filePath, null, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                filePath, null, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                filePath, null, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                filePath, null, null, null, SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    filePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, SampleContentBytes, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    null, SampleContentBytes, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2, null,
                null, "", S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
         
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, S3CannedACL.AuthenticatedRead, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2,
                    null, null, SampleContent, S3CannedACL.AuthenticatedRead, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV1N, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingMetadataModeKMS_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2,
                    filePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    filePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap_V2SecurityProfile()
        {
            fileConfigV2.SecurityProfile = SecurityProfile.V2;
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestRangeGetIsDisabled()
        {
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
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
            s3EncryptionClientMetadataModeKMSV1N.PutObject(putObjectRequest);

            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = putObjectRequest.Key
            };

            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV1N.EndGetObject(
                    s3EncryptionClientMetadataModeKMSV1N.BeginGetObject(getObjectRequest, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV2.EndGetObject(
                    s3EncryptionClientMetadataModeKMSV2.BeginGetObject(getObjectRequest, null, null));
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
                PutObjectResponse response = s3EncryptionClientMetadataModeKMSV1N.EndPutObject(
                    s3EncryptionClientMetadataModeKMSV1N.BeginPutObject(requestV1, null, null));
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
                PutObjectResponse response = s3EncryptionClientMetadataModeKMSV2.EndPutObject(
                    s3EncryptionClientMetadataModeKMSV2.BeginPutObject(requestV2, null, null));
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
                s3EncryptionClientMetadataModeKMSV1N.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMSV1N.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
            
            AssertExtensions.ExpectException(() =>
            {
                s3EncryptionClientMetadataModeKMSV2.EndInitiateMultipartUpload(
                    s3EncryptionClientMetadataModeKMSV2.BeginInitiateMultipartUpload(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }
#endif
    }
}
