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
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
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
        private static readonly string filePath = Path.Combine(Path.GetTempPath(), "EncryptionPutObjectFileV2.txt");
        
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
                var response = EncryptionTests.CallAsyncTask(
                    kmsClient.CreateKeyAsync(new CreateKeyRequest
                    {
                        Description = "Key for .NET integration tests.",
                        Origin = OriginType.AWS_KMS,
                        KeyUsage = KeyUsageType.ENCRYPT_DECRYPT
                    }));
                kmsKeyID = response.KeyMetadata.KeyId;
            }
            
            var asymmetricEncryptionMaterials = new EncryptionMaterials(RSA.Create());
            var symmetricEncryptionMaterials = new EncryptionMaterials(Aes.Create());
            var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);

            AmazonS3CryptoConfiguration config = new AmazonS3CryptoConfiguration()
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

            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.Write(sampleContent);
                writer.Flush();
            }
            bucketName = EncryptionTests.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrap, GetType().Name));
        }

        protected override void Dispose(bool disposing)
        {
            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                EncryptionTests.CallAsyncTask(
                    kmsClient.ScheduleKeyDeletionAsync(new ScheduleKeyDeletionRequest
                    {
                        KeyId = kmsKeyID,
                        PendingWindowInDays = 7
                    }));
            }

            EncryptionTests.CallAsyncTask(
                UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            s3EncryptionClientMetadataModeAsymmetricWrap.Dispose();
            s3EncryptionClientFileModeAsymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrap.Dispose();
            s3EncryptionClientFileModeSymmetricWrap.Dispose();
            s3EncryptionClientMetadataModeKMS.Dispose();
            s3EncryptionClientFileModeKMS.Dispose();
            if (File.Exists(filePath))
                File.Delete(filePath);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null, null, null,
                sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null, null, sampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, sampleContentBytes,
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetTemperedContentUsingMetadataMode()
        {
            // Put encrypted content
            string key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the content
            await TemperCipherTextAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<AmazonCryptoException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            }, "Failed to decrypt: mac check in GCM failed");
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetTemperedCekAlgUsingMetadataMode()
        {
            // Put encrypted content
            string key = await PutContentAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<InvalidDataException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeAsymmetricWrap, bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrap, null, null,
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrap, null, null,
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrap, null, null,
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeKMS, 
                    filePath, null, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetStreamUsingMetadataModeKMS()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, sampleContentBytes, 
                null, null, sampleContent, bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeKMS, 
                    null, sampleContentBytes, null, null, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentUsingMetadataModeKMS()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, 
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);
        }
        
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetContentWithTemperedEncryptionContextUsingMetadataModeKMS()
        {
            // Put encrypted content
            string key = await PutContentAsync(s3EncryptionClientMetadataModeKMS, null, null, 
                sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName).ConfigureAwait(false);

            // Temper the cek algorithm
            await TemperCekAlgEncryptionContextAsync(s3Client, bucketName, key, S3CannedACL.AuthenticatedRead);

            // Verify
            AssertExtensions.ExpectException<InvalidCiphertextException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestGetAsync(key, sampleContent, s3EncryptionClientMetadataModeKMS, bucketName));
            });
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, 
                "", S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task PutGetNullContentContentUsingMetadataModeKMS()
        {
            await EncryptionTests.TestPutGetAsync(s3EncryptionClientMetadataModeKMS, null, null, 
                null, S3CannedACL.AuthenticatedRead, "", bucketName).ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.TestPutGetAsync(s3EncryptionClientFileModeKMS, null,
                    null, sampleContent, S3CannedACL.AuthenticatedRead, sampleContent, bucketName));
            }, InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingMetadataModeAsymmetricWrap()
        {
            await EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingMetadataModeSymmetricWrap()
        {
            await EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingInstructionFileAsymmetricWrap()
        {
            await EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionUsingInstructionFileSymmetricWrap()
        {
            await EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrap, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async Task MultipartEncryptionTestMetadataModeKMS()
        {
            await EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTests.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMS, bucketName));
            }, InstructionAndKMSErrorMessage);
        }
        
        public static async Task<string> PutContentAsync(AmazonS3Client s3EncryptionClient, string filePath, 
            byte[] inputStreamBytes, string contentBody, S3CannedACL cannedACL, string expectedContent, string bucketName)
        {
            var random = new Random();
            string key = $"key-{random.Next()}";
            PutObjectRequest request = new PutObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
                FilePath = filePath,
                InputStream = inputStreamBytes == null ? null : new MemoryStream(inputStreamBytes),
                ContentBody = contentBody,
                CannedACL = cannedACL
            };
            PutObjectResponse response = await s3EncryptionClient.PutObjectAsync(request).ConfigureAwait(false);
            return key;
        }

        private static async Task TemperCipherTextAsync(AmazonS3Client s3Client, string bucketName, string key, string cannedACL)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
            };

            using (GetObjectResponse getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                byte[] data = getObjectResponse.ResponseStream.ReadAllBytes();
                
                // Flip the stored cipher text first byte and put back
                data[0] = (byte)~data[0];
                PutObjectRequest putObjectRequest = new PutObjectRequest()
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
            GetObjectRequest getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
            };

            using (GetObjectResponse getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                byte[] data = getObjectResponse.ResponseStream.ReadAllBytes();
                PutObjectRequest putObjectRequest = new PutObjectRequest()
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
            GetObjectRequest getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketName,
                Key = key,
            };

            using (GetObjectResponse getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false))
            {
                byte[] data = getObjectResponse.ResponseStream.ReadAllBytes();
                PutObjectRequest putObjectRequest = new PutObjectRequest()
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
