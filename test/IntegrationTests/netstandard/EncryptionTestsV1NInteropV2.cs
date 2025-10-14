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
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV1NInteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessageV1N = "AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                                                                "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private const string InstructionAndKMSErrorMessageV2 = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private static readonly string LegacyReadWhenLegacyDisabledMessage = $"The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration {nameof(SecurityProfile.V2)}." +
                                                                             $" Retry with {nameof(SecurityProfile.V2AndLegacy)} enabled or reencrypt the object.";
        
        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);
        private string bucketName;
        private string kmsKeyID;

        private AmazonS3CryptoConfigurationV2 metadataConfigV2;
        private AmazonS3CryptoConfigurationV2 fileConfigV2;

#pragma warning disable 0618
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeAsymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeSymmetricWrapV1N;
        private AmazonS3EncryptionClient s3EncryptionClientMetadataModeKMSV1N;
        private AmazonS3EncryptionClient s3EncryptionClientFileModeKMSV1N;
#pragma warning restore 0618

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2WithEC;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2WithEC;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2WithoutEC;

        public EncryptionTestsV1NInteropV2(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsIdAsync().GetAwaiter().GetResult();

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
            var kmsEncryptionMaterialsV2WithEC = new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            var kmsEncryptionMaterialsV2WithoutEC = new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext);

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata,
            };

            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };

#pragma warning disable 0618
            s3EncryptionClientMetadataModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(asymmetricEncryptionMaterialsV1N);
            s3EncryptionClientFileModeAsymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, asymmetricEncryptionMaterialsV1N);
            s3EncryptionClientMetadataModeSymmetricWrapV1N = new AmazonS3EncryptionClient(symmetricEncryptionMaterialsV1N);
            s3EncryptionClientFileModeSymmetricWrapV1N = new AmazonS3EncryptionClient(configV1N, symmetricEncryptionMaterialsV1N);
            s3EncryptionClientMetadataModeKMSV1N = new AmazonS3EncryptionClient(kmsEncryptionMaterialsV1N);
            s3EncryptionClientFileModeKMSV1N = new AmazonS3EncryptionClient(configV1N, kmsEncryptionMaterialsV1N);
#pragma warning restore 0618

            s3EncryptionClientMetadataModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, asymmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeAsymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, asymmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(metadataConfigV2, symmetricEncryptionMaterialsV2);
            s3EncryptionClientFileModeSymmetricWrapV2 = new AmazonS3EncryptionClientV2(fileConfigV2, symmetricEncryptionMaterialsV2);
            s3EncryptionClientMetadataModeKMSV2WithEC = new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2WithEC);
            s3EncryptionClientFileModeKMSV2WithEC = new AmazonS3EncryptionClientV2(fileConfigV2, kmsEncryptionMaterialsV2WithEC);
            s3EncryptionClientMetadataModeKMSV2WithoutEC = new AmazonS3EncryptionClientV2(metadataConfigV2, kmsEncryptionMaterialsV2WithoutEC);

            using (var writer = File.CreateText(filePath))
            {
                writer.Write(SampleContent);
            }
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrapV1N));
        }

        protected override void Dispose(bool disposing)
        {
            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName));
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
            
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, "", "", bucketName).ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, "", "", bucketName).ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    filePath, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    filePath, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    null, SampleContentBytes, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    null, SampleContentBytes, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PerRequestEncryptionContextOnV1ObjectRejected()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            // V1 Object does not support request level EC.
            // Fails as we are trying to put V1 object with request EC
            var exceptionOnPut = await Assert.ThrowsAsync<ArgumentException>(async () =>
            {
                await EncryptionTestsUtils.TestPutAsync(
                    s3EncryptionClientMetadataModeKMSV1N,
                    null, null, SampleContent,
                    bucketName, key, TestConstants.RequestEC1).ConfigureAwait(false);
            });
            Assert.Contains(TestConstants.ECNotSupported, exceptionOnPut.Message);
                
            await EncryptionTestsUtils.TestPutAsync(
                s3EncryptionClientMetadataModeKMSV1N,
                null, null, SampleContent,
                bucketName, key).ConfigureAwait(false);
            
            // Fails as this is trying to get V1 object with request EC
            var exceptionOnGetWithV1Client = await Assert.ThrowsAsync<ArgumentException>(async () =>
            {
                await EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC1).ConfigureAwait(false);
            });
            Assert.Contains(TestConstants.ECNotSupported, exceptionOnGetWithV1Client.Message);
            
            // Fails as this is trying to get V1 object with request EC even in V2AndLegacy
            var exceptionOnGetWithV2Client = await Assert.ThrowsAsync<ArgumentException>(async () =>
            {
                await EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV2WithoutEC, 
                    bucketName, TestConstants.RequestEC1).ConfigureAwait(false);
            });
            Assert.Contains(TestConstants.ECNotSupported, exceptionOnGetWithV2Client.Message);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void V2PutV1GetWithSameRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            await EncryptionTestsUtils.TestPutAsync(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1).ConfigureAwait(false);
            
            // Succeeds as this is trying to get v2 object even with v1 client
            await EncryptionTestsUtils.TestGetAsync(
                key, SampleContent, s3EncryptionClientMetadataModeKMSV1N,
                bucketName, TestConstants.RequestEC1).ConfigureAwait(false);
            
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void V2PutV1GetWithDifferentRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            await EncryptionTestsUtils.TestPutAsync(
                s3EncryptionClientMetadataModeKMSV2WithoutEC,
                null, null, SampleContent,
                bucketName, key, TestConstants.RequestEC1).ConfigureAwait(false);
            var exception = await Assert.ThrowsAsync<AmazonS3EncryptionClientException>(async () =>
            {
                await EncryptionTestsUtils.TestGetAsync(
                    key, SampleContent, s3EncryptionClientMetadataModeKMSV1N, 
                    bucketName, TestConstants.RequestEC2).ConfigureAwait(false);
            });
            Assert.Contains(TestConstants.ECNotMatched, exception.Message);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N,
                    null, null, SampleContent, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC,
                    null, null, SampleContent, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV1N, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV1N, s3EncryptionClientFileModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV2WithEC, s3EncryptionClientMetadataModeKMSV1N, bucketName)
                .ConfigureAwait(false);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV2WithoutEC,
                s3EncryptionClientMetadataModeKMSV1N, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1).ConfigureAwait(false);
            
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV1N,
                    s3EncryptionClientMetadataModeKMSV2WithoutEC, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1));
            }, TestConstants.ECNotSupported);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV2WithEC, s3EncryptionClientFileModeKMSV1N, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV1N, s3EncryptionClientFileModeKMSV2WithEC, bucketName));
            }, InstructionAndKMSErrorMessageV1N);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingMetadataModeKMS_V2SecurityProfile()
        {
            metadataConfigV2.SecurityProfile = SecurityProfile.V2;

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV1N, s3EncryptionClientMetadataModeKMSV2WithEC,
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
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV1N, s3EncryptionClientMetadataModeAsymmetricWrapV2,
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
                    EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV1N, s3EncryptionClientFileModeAsymmetricWrapV2,
                        filePath, null, null, SampleContent, bucketName)
                );
            }, LegacyReadWhenLegacyDisabledMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestRangeGetIsDisabled()
        {
            AssertExtensions.ExpectException<NotSupportedException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.AttemptRangeGet(s3EncryptionClientFileModeAsymmetricWrapV1N, bucketName));
            }, EncryptionTestsUtils.RangeGetNotSupportedMessage);

            AssertExtensions.ExpectException<NotSupportedException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.AttemptRangeGet(s3EncryptionClientFileModeAsymmetricWrapV2, bucketName));
            }, EncryptionTestsUtils.RangeGetNotSupportedMessage);
        }
    }
}
