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

using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Util;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Xunit;

#if AWS_APM_API
using System;
using System.Text.RegularExpressions;
using Amazon.S3.Model;
#endif

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage =
            "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string SampleContent = "Encryption Client V2 Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);

        private string filePath =
            EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private static string bucketName;
        private static string kmsKeyID;

        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrap;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrap;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrap;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrap;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMS;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMS;

        public EncryptionTestsV2() : base(KmsKeyIdProvider.Instance)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsId();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterials = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterials = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);

            var kmsEncryptionMaterials =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            var fileConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            var metadataConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };

            s3EncryptionClientMetadataModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, symmetricEncryptionMaterials);

            s3EncryptionClientFileModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, symmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientFileModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClientV2(metadataConfig, kmsEncryptionMaterials);

            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClientV2(fileConfig, kmsEncryptionMaterials);

            using (var writer = File.CreateText(filePath))
            {
                writer.Write(SampleContent);
            }

            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileModeSymmetricWrap);
        }

        protected override void Dispose(bool disposing)
        {
            AmazonS3Util.DeleteS3BucketWithObjects(s3EncryptionClientMetadataModeSymmetricWrap, bucketName);
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () => { EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMS, bucketName); },
                typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, filePath, null, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, SampleContentBytes,
                null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, "", "",
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, "", "",
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, null, "",
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, null, "",
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMS, filePath, null, null, SampleContent,
                        bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, SampleContentBytes, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMS, null, SampleContentBytes, null,
                        SampleContent, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMS, null, null, SampleContent,
                        SampleContent, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () => { EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMS, bucketName); },
                typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

#if AWS_APM_API
        private static readonly Regex APMKMSErrorRegex = new Regex("Please use the synchronous version instead.");

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestGetObjectAPMKMS()
        {
            PutObjectRequest putObjectRequest = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                ContentBody = SampleContent,
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

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestPutObjectAPMKMS()
        {
            PutObjectRequest request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                ContentBody = SampleContent,
            };

            AssertExtensions.ExpectException(() =>
            {
                PutObjectResponse response = s3EncryptionClientMetadataModeKMS.EndPutObject(
                    s3EncryptionClientMetadataModeKMS.BeginPutObject(request, null, null));
            }, typeof(NotSupportedException), APMKMSErrorRegex);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestInitiateMultipartUploadAPMKMS()
        {
            InitiateMultipartUploadRequest request = new InitiateMultipartUploadRequest()
            {
                BucketName = bucketName,
                Key = $"key-{Guid.NewGuid()}",
                StorageClass = S3StorageClass.OneZoneInfrequentAccess,
                ContentType = "text/html",
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