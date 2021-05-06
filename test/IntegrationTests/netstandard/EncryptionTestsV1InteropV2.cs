﻿/*
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
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV1InteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKmsErrorMessage = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                             "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private static readonly string LegacyReadWhenLegacyDisabledMessage = $"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V2)}." +
                                                                             $" Retry with {nameof(SecurityProfile.V2AndLegacy)} enabled or reencrypt the object.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);
        private string bucketName;
        private string kmsKeyID;

        private AmazonS3CryptoConfigurationV2 fileConfigV2;
        private AmazonS3CryptoConfigurationV2 metadataConfigV2;

        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1;
        private Amazon.S3.Encryption.AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1;

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTestsV1InteropV2(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsIdAsync().GetAwaiter().GetResult();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(rsa);
            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);

            var symmetricEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(aes);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);

            var kmsEncryptionMaterialsV1 = new Amazon.S3.Encryption.EncryptionMaterials(kmsKeyID);
            var kmsEncryptionMaterialsV2 = new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            var configV1 = new Amazon.S3.Encryption.AmazonS3CryptoConfiguration
            {
                StorageMode = Amazon.S3.Encryption.CryptoStorageMode.InstructionFile
            };

            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };

            s3EncryptionClientMetadataModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeAsymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, asymmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1);
            s3EncryptionClientFileModeSymmetricWrapV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, symmetricEncryptionMaterialsV1);
            s3EncryptionClientMetadataModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(kmsEncryptionMaterialsV1);
            s3EncryptionClientFileModeKMSV1 = new Amazon.S3.Encryption.AmazonS3EncryptionClient(configV1, kmsEncryptionMaterialsV1);

            s3EncryptionClientMetadataModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, asymmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, asymmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, symmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, symmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeKMSV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2);
            s3EncryptionClientFileModeKMSV2 = new AmazonS3EncryptionClientV2(fileConfigV2, kmsEncryptionMaterialsV2);

            using (var writer = File.CreateText(filePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrapV1));
        }

        protected override void Dispose(bool disposing)
        {
            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV1.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV1.Dispose();
            s3EncryptionClientMetadataModeKMSV1.Dispose();
            s3EncryptionClientFileModeKMSV1.Dispose();

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
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, SampleContent, bucketName));
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV2,
                    null, SampleContentBytes, null, SampleContent, bucketName); });
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV2,
                    null, null, SampleContent, SampleContent, bucketName));
            }, InstructionAndKmsErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV1, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV1, s3EncryptionClientFileModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV1, s3EncryptionClientFileModeKMSV2, bucketName));
            }, InstructionAndKmsErrorMessage);
        }


        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingMetadataModeKMS_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1, s3EncryptionClientMetadataModeKMSV2,
                        filePath, null, null, SampleContent, bucketName)
                );
            }, LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                        filePath, null, null, SampleContent, bucketName)
                );
            }, LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap_V2SecurityProfile()
        {
            fileConfigV2.SecurityProfile = SecurityProfile.V2;
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1, s3EncryptionClientFileModeAsymmetricWrapV2,
                        filePath, null, null, SampleContent, bucketName)
                );
            }, LegacyReadWhenLegacyDisabledMessage);
        }
    }
}
