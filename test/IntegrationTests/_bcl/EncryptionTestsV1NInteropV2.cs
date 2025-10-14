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
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Tests.Common;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Util;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV1NInteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessageV1N =
            "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string InstructionAndKMSErrorMessageV2 =
            "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private static readonly string LegacyReadWhenLegacyDisabledMessage =
            $"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V2)}." +
            $" Retry with {nameof(SecurityProfile.V2AndLegacy)} enabled or reencrypt the object.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);

        private string filePath =
            EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private static string bucketName;
        private static string kmsKeyID;

        private readonly AmazonS3CryptoConfigurationV2 metadataConfigV2;
        private readonly AmazonS3CryptoConfigurationV2 fileConfigV2;

#pragma warning disable 0618
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private static AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;
#pragma warning restore 0618

        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2WithEC;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2WithEC;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2WithoutEC;

        public EncryptionTestsV1NInteropV2() : base(KmsKeyIdProvider.Instance)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsId();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterialsV1N = new EncryptionMaterials(rsa);
            var symmetricEncryptionMaterialsV1N = new EncryptionMaterials(aes);
            var kmsEncryptionMaterialsV1N = new EncryptionMaterials(kmsKeyID);
            var configV1N = new AmazonS3CryptoConfiguration()
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV2WithEC =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            var kmsEncryptionMaterialsV2WithoutEC =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext );

            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata,
            };

#pragma warning disable 0618
            s3EncryptionClientMetadataModeAsymmetricWrapV1N =
                new AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1N);

            s3EncryptionClientFileModeAsymmetricWrapV1N =
                new AmazonS3EncryptionClient(configV1N, asymmetricEncryptionMaterialsV1N);

            s3EncryptionClientMetadataModeSymmetricWrapV1N =
                new AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1N);

            s3EncryptionClientFileModeSymmetricWrapV1N =
                new AmazonS3EncryptionClient(configV1N, symmetricEncryptionMaterialsV1N);

            s3EncryptionClientMetadataModeKMSV1N = new AmazonS3EncryptionClient(kmsEncryptionMaterialsV1N);

            s3EncryptionClientFileModeKMSV1N = new AmazonS3EncryptionClient(configV1N, kmsEncryptionMaterialsV1N);
#pragma warning restore 0618

            s3EncryptionClientMetadataModeAsymmetricWrapV2 =
                new AmazonS3EncryptionClientV2(metadataConfigV2, asymmetricEncryptionMaterialsV2);

            s3EncryptionClientFileModeAsymmetricWrapV2 =
                new AmazonS3EncryptionClientV2(fileConfigV2, asymmetricEncryptionMaterialsV2);

            s3EncryptionClientMetadataModeSymmetricWrapV2 =
                new AmazonS3EncryptionClientV2(metadataConfigV2, symmetricEncryptionMaterialsV2);

            s3EncryptionClientFileModeSymmetricWrapV2 =
                new AmazonS3EncryptionClientV2(fileConfigV2, symmetricEncryptionMaterialsV2);

            s3EncryptionClientMetadataModeKMSV2WithEC =
                new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2WithEC);

            s3EncryptionClientFileModeKMSV2WithEC = new AmazonS3EncryptionClientV2(fileConfigV2, kmsEncryptionMaterialsV2WithEC);

            s3EncryptionClientMetadataModeKMSV2WithoutEC
                = new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2WithoutEC);
            
            using (var writer = File.CreateText(filePath))
            {
                writer.Write(SampleContent);
            }

            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileModeAsymmetricWrapV1N);
        }

        protected override void Dispose(bool disposing)
        {
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
            s3EncryptionClientMetadataModeKMSV2WithEC.Dispose();
            s3EncryptionClientFileModeKMSV2WithEC.Dispose();
            s3EncryptionClientMetadataModeKMSV2WithoutEC.Dispose();

            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV1N,
                s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV1N,
                s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV2WithEC,
                        s3EncryptionClientFileModeKMSV1N, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV1N,
                        s3EncryptionClientFileModeKMSV2WithEC, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV2WithEC,
                s3EncryptionClientMetadataModeKMSV1N, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV1N,
                s3EncryptionClientMetadataModeKMSV2WithEC, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                filePath, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N,
                filePath, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV1N,
                filePath, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV1N,
                filePath, null, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N,
                s3EncryptionClientFileModeSymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N,
                s3EncryptionClientFileModeSymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, "", "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, null, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV1N,
                s3EncryptionClientFileModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, SampleContent, bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, "", "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null,
                null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, "", bucketName);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PerRequestEncryptionContextOnV1ObjectRejected()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            // V1 Object does not support request level EC.
            // Fails as we are trying to put V1 object with request EC
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPut(
                    s3EncryptionClientMetadataModeKMSV1N,
                    null, null, SampleContent,
                    bucketName, key, TestConstants.RequestEC1);
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
            AssertExtensions.ExpectException( () =>
            {
                EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(
                    s3EncryptionClientMetadataModeKMSV1N,
                    null, null, SampleContent,
                    bucketName, key, TestConstants.RequestEC1));
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
                
            EncryptionTestsUtils.TestPut(
                s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent,
                bucketName, key);
            
            // Fails as this is trying to get V1 object with request EC
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestGet(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC1);
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC1));
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
            
            // Fails as this is trying to get V1 object with request EC even in V2AndLegacy
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestGet(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV2WithoutEC, 
                    bucketName, TestConstants.RequestEC1);
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV2WithoutEC, 
                    bucketName, TestConstants.RequestEC1));
            }, typeof(ArgumentException), TestConstants.ECNotSupported);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void V2PutV1GetWithSameRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            EncryptionTestsUtils.TestPut(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1);
            
            // Succeeds as this is trying to get v2 object even with v1 client
            EncryptionTestsUtils.TestGet(
                key, SampleContent, s3EncryptionClientMetadataModeKMSV1N,
                bucketName, TestConstants.RequestEC1);
            
            EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1));
            
            EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(
                key, SampleContent, s3EncryptionClientMetadataModeKMSV1N,
                bucketName, TestConstants.RequestEC1));
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void V2PutV1GetWithDifferentRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            EncryptionTestsUtils.TestPut(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1);
            AssertExtensions.ExpectException(() =>
                {
                EncryptionTestsUtils.TestGet(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC2);
            }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
            
            EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1));
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC2));
            }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV1N,
                s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV1N,
                s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV1N,
                s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV2WithEC,
                s3EncryptionClientMetadataModeKMSV1N, bucketName);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV1N,
                s3EncryptionClientMetadataModeKMSV2WithEC, bucketName);
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV2WithoutEC,
                s3EncryptionClientMetadataModeKMSV1N, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV1N,
                s3EncryptionClientMetadataModeKMSV2WithoutEC, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV2WithEC,
                        s3EncryptionClientFileModeKMSV1N, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV1N,
                        s3EncryptionClientFileModeKMSV2WithEC, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeKMS_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV1N,
                    s3EncryptionClientMetadataModeKMSV2WithEC,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap_V2SecurityProfile()
        {
            fileConfigV2.SecurityProfile = SecurityProfile.V2;
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV1N,
                    s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonCryptoException), LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestRangeGetIsDisabled()
        {
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName);
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }
    }
}