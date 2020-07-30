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
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Xunit;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime.Internal.Util;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessage = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
                                                             "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string sampleContent = "Encryption Client Testing!";

        private static readonly byte[] sampleContentBytes = Encoding.UTF8.GetBytes(sampleContent);
        private static string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);
        
        private string bucketName;
        private string kmsKeyID;

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrap;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMS;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMS;

        private AmazonS3Client s3Client;
        
        public EncryptionTestsV2()
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                var response = EncryptionTestsUtils.CallAsyncTask(
                    kmsClient.CreateKeyAsync(new CreateKeyRequest
                    {
                        Description = "Key for .NET integration tests.",
                        Origin = OriginType.AWS_KMS,
                        KeyUsage = KeyUsageType.ENCRYPT_DECRYPT
                    }));
                kmsKeyID = response.KeyMetadata.KeyId;
            }

            var rsa = RSA.Create();
            var aes = Aes.Create();
            
            var asymmetricEncryptionMaterials = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterials = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterials = new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            var config = new AmazonS3CryptoConfigurationV2
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            s3EncryptionClientMetadataModeAsymmetricWrap = new AmazonS3EncryptionClientV2(asymmetricEncryptionMaterials);
            s3EncryptionClientFileModeAsymmetricWrap = new AmazonS3EncryptionClientV2(config, asymmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeSymmetricWrap = new AmazonS3EncryptionClientV2(symmetricEncryptionMaterials);
            s3EncryptionClientFileModeSymmetricWrap = new AmazonS3EncryptionClientV2(config, symmetricEncryptionMaterials);
            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClientV2(kmsEncryptionMaterials);
            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClientV2(config, kmsEncryptionMaterials);

            s3Client = new AmazonS3Client();

            using (var writer = new StreamWriter(filePath))
            {
                writer.Write(sampleContent);
                writer.Flush();
            }
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrap, GetType().Name));
        }

        protected override void Dispose(bool disposing)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                EncryptionTestsUtils.CallAsyncTask(
                    kmsClient.ScheduleKeyDeletionAsync(new ScheduleKeyDeletionRequest
                    {
                        KeyId = kmsKeyID,
                        PendingWindowInDays = 7
                    }));
            }

            EncryptionTestsUtils.CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null, null, null,
                sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetTemperedContentUsingMetadataMode()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the content
            await TemperCipherTextAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<AmazonCryptoException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            }, "Failed to decrypt: mac check in GCM failed");
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetTemperedCekAlgUsingMetadataMode()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<InvalidDataException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS,
                    filePath, null, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS,
                    null, sampleContentBytes, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentWithTemperedEncryptionContextUsingMetadataModeKMS()
        {
            // Put encrypted content
            var key = await PutContentAsync(s3EncryptionClientMetadataModeKMS, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgEncryptionContextAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<InvalidCiphertextException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeKMS, bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null,
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMS, null,
                    null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingInstructionFileAsymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingInstructionFileSymmetricWrap()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEnecryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMS, bucketName));
            }, InstructionAndKMSErrorMessage);
        }
        
        public static async Task<string> PutContentAsync(AmazonS3Client s3EncryptionClient, string filePath, 
            byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
        {
            var random = new Random();
            var key = $"key-{random.Next()}";
            var request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
                CannedACL = cannedACL
            };
            var response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            return key;
        }

        private static async Task TemperCipherTextAsync(AmazonS3Client s3Client, string bucketName, string key, string cannedACL)
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
                    CannedACL = cannedACL
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                await s3Client.PutObjectAsync(putObjectRequest).ConfigureAwait(false);
            }
        }

        private static async Task TemperCekAlgAsync(AmazonS3Client s3Client, string bucketName, string key, string cannedACL)
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
                    CannedACL = cannedACL
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
        
        private static async Task TemperCekAlgEncryptionContextAsync(AmazonS3Client s3Client, string bucketName, string key, string cannedACL)
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
                    CannedACL = cannedACL
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
