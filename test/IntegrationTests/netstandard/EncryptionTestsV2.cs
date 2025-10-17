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
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Tests.Common;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using Amazon.S3.Model;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage =
            "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        
        private const string sampleContent = "Encryption Client Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);

        private string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);
        
        private string bucketName;
        private string kmsKeyID;

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSWithEC;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSWithEC;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSWithoutEC;

        private AmazonS3Client s3Client;

        public EncryptionTestsV2(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsIdAsync().GetAwaiter().GetResult();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterials = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterials = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsWithEC =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            var kmsEncryptionMaterialsWithoutEC =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext);
            var fileConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };


            var metadataConfig = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };

            s3EncryptionClientMetadataModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, asymmetricEncryptionMaterials);
            s3EncryptionClientFileModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, asymmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, symmetricEncryptionMaterials);
            s3EncryptionClientFileModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, symmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeKMSWithEC = new AmazonS3EncryptionClientV2(metadataConfig, kmsEncryptionMaterialsWithEC);
            s3EncryptionClientFileModeKMSWithEC = new AmazonS3EncryptionClientV2(fileConfig, kmsEncryptionMaterialsWithEC);
            s3EncryptionClientMetadataModeKMSWithoutEC = new AmazonS3EncryptionClientV2(metadataConfig, kmsEncryptionMaterialsWithoutEC);

            s3Client = new AmazonS3Client();

            using (var writer = new StreamWriter(File.OpenWrite(filePath)))
            {
                writer.Write(sampleContent);
                writer.Flush();
            }

            bucketName =
                EncryptionTestsUtils.CallAsyncTask(
                    UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrap));
        }

        protected override void Dispose(bool disposing)
        {
            EncryptionTestsUtils.CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMSWithEC.Dispose();
            s3EncryptionClientFileModeKMSWithEC.Dispose();
            s3EncryptionClientMetadataModeKMSWithoutEC.Dispose();
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null,
                null,
                sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null,
                    sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null,
                    sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null,
                sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetTemperedContentUsingMetadataMode()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the content
            await TemperCipherTextAsync(s3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException<AmazonCryptoException>(
                () =>
                {
                    AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                        s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
                }, "Failed to decrypt: mac check in GCM failed");
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetTemperedCekAlgUsingMetadataMode()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgAsync(s3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException<InvalidDataException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent,
                    s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                "", "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                "", "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSWithEC,
                    filePath, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithEC, null, sampleContentBytes,
                null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSWithEC,
                    null, sampleContentBytes, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithEC, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingKMSWithSameRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            var encryptionContext = new Dictionary<string, string>(TestConstants.RequestEC1);
            var expectedEncryptionContext = encryptionContext;

            expectedEncryptionContext.Add(TestConstants.XAmzEncryptionContextCekAlg, TestConstants.XAmzAesGcmCekAlgValue);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                sampleContent, sampleContent, bucketName, key, TestConstants.RequestEC1, TestConstants.RequestEC1).ConfigureAwait(false);
            
            // This proves the material description in S3 is what we expect.
            await EncryptionTestsUtils.TestGetAsync(
                key, sampleContent, s3Client, bucketName,
                TestConstants.RequestEC1, false, true, expectedEncryptionContext)
                .ConfigureAwait(false);
            
            // This proves the EC we are sending to KMS is actually the EC we expect without using S3EC at all.
            await CommonUtils.DecryptDataKeyWithoutS3ECAsync(key, s3Client, bucketName,
                TestConstants.XAmzKeyV2, expectedEncryptionContext, TestConstants.RequestEC1)
                .ConfigureAwait(false);
            
            // This is expected to fail as TestConstants.RequestEC1 does not have reserved key.
            AssertExtensions.ExpectException<InvalidCiphertextException>(() =>
            {
                AsyncHelpers.RunSync(() => CommonUtils.DecryptDataKeyWithoutS3ECAsync(key, s3Client, bucketName,
                    TestConstants.XAmzKeyV2, TestConstants.RequestEC1, TestConstants.RequestEC1));
            });
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingKMSWithDifferentRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            await EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeKMSWithoutEC, null, null, 
                sampleContent, bucketName, key, TestConstants.RequestEC1).ConfigureAwait(false);
            
            AssertExtensions.ExpectException<AmazonS3EncryptionClientException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent, 
                    s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.RequestEC2));
            }, TestConstants.ECNotMatched);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingKMSWithNoECAtAll()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutContentUsingKMSWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeKMSWithEC, 
                    null, null, sampleContent, bucketName, key, TestConstants.RequestEC1));
            }, TestConstants.MultipleECErrorMesage);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentUsingKMSWithReservedKeyInRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                        sampleContent, bucketName, key, TestConstants.EncryptionContextWithReservedKey));
            }, TestConstants.ReservedKeyInECErrorMessage);
            
            // The version of encrypted object can only be determined after getting object from S3. 
            // So, this is a dummy put to test get object fails.
            await EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                    sampleContent, bucketName, key)
                .ConfigureAwait(false);
            
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent, 
                    s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.EncryptionContextWithReservedKey));
            }, TestConstants.ReservedKeyInECErrorMessage);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionTestMetadataModeKMSWithSameRequestEC()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, 
                TestConstants.RequestEC1, TestConstants.RequestEC1);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMSWithDifferentRequestEC()
        {
            AssertExtensions.ExpectException<AmazonS3EncryptionClientException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, 
                    TestConstants.RequestEC1, TestConstants.RequestEC2));
            }, TestConstants.ECNotMatched);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingAsymmetricWrapWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeAsymmetricWrap, 
                    null, null, sampleContent, bucketName, key, TestConstants.RequestEC1));
            }, TestConstants.ECNotSupported);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingSymmetricWrapWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeSymmetricWrap, 
                    null, null, sampleContent, bucketName, key, TestConstants.RequestEC1));
            }, TestConstants.ECNotSupported);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetContentWithTemperedEncryptionContextUsingMetadataModeKMS()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeKMSWithEC, null, null,
                sampleContent, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgEncryptionContextAsync(s3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException<InvalidCiphertextException>(() =>
            {
                AsyncHelpers.RunSync(() =>
                    EncryptionTestsUtils.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeKMSWithEC,
                        bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithEC, null, null,
                "", "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSWithEC, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task PutGetNullContentContentUsingMetadataModeKMSCalculateMD5()
        {
            await EncryptionTestsUtils.TestPutGetCalculateMD5Async(s3EncryptionClientMetadataModeKMSWithEC, s3EncryptionClientMetadataModeKMSWithEC, null, null,
                null, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSWithEC, null,
                    null, sampleContent, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionUsingInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap,
                bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSWithEC, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public async Task MultipartEncryptionTestMetadataModeKMSCalculateMD5()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestCalculateMD5Async(s3EncryptionClientMetadataModeKMSWithEC, s3EncryptionClientMetadataModeKMSWithEC, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEnecryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    AsyncHelpers.RunSync(() =>
                        EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSWithEC, bucketName));
                }, InstructionAndKMSErrorMessage);
        }

        public static async Task<string> PutContentAsync(AmazonS3Client s3EncryptionClient, string filePath,
            byte[] inputStreamBytes, string contentBody, string expectedContent, string bucketName)
        {
            var key = $"key-{Guid.NewGuid()}";
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
            };
            var response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            return key;
        }

        private static async Task TemperCipherTextAsync(AmazonS3Client s3Client, string bucketName, string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();

                // Flip the stored cipher text first byte and put back
                data[0] = (byte)~data[0];
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TemperCekAlgAsync(AmazonS3Client s3Client, string bucketName, string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-cek-alg"))
                    {
                        putObjectRequest.Metadata.Add(metadataKey, "Unsupported");
                    }
                    else
                    {
                        putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                    }
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TemperCekAlgEncryptionContextAsync(AmazonS3Client s3Client, string bucketName,
            string key)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key
            };

            using (var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                var data = getObjectResponse.ResponseStream.ReadAllBytes();
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketName,
                    Key = key,
                    InputStream = new MemoryStream(data)
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-matdesc"))
                    {
                        continue;
                    }

                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }
    }
}