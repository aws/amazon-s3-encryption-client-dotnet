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
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV4  : TestBase<AmazonS3Client>
    {
        private const string UploadPartsInIncorrectSequence =
            "Upload Parts must be in correct sequence. Request part number 2 must be >= to 3";
        
        private const string InstructionAndKMSErrorMessage =
            "AmazonS3EncryptionClientV4 only supports KMS key wrapping in metadata storage mode. " +
            "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string TamperCipherTextError =
            "Failed to decrypt: mac check in GCM failed";
        
        private const string KeyCommitmentMismatchErrorMessage =
            "Stored key commitment does not match the derived key commitment value";

        private const string SampleContent = "Encryption Client v4 Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);

        private string filePath =
            EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private static string bucketName;
        private static string kmsKeyID;

        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrap;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrap;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrap;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrap;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMS;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMS;

        private static AmazonS3Client vanillaS3Client;

        public EncryptionTestsV4() : base(KmsKeyIdProvider.Instance)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsId();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterials = new EncryptionMaterialsV4(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterials = new EncryptionMaterialsV4(aes, SymmetricAlgorithmType.AesGcm);

            var kmsEncryptionMaterials =
                new EncryptionMaterialsV4(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            var fileConfig = new AmazonS3CryptoConfigurationV4
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };

            var metadataConfig = new AmazonS3CryptoConfigurationV4
            {
                StorageMode = CryptoStorageMode.ObjectMetadata
            };

            s3EncryptionClientMetadataModeSymmetricWrap =
                new AmazonS3EncryptionClientV4(metadataConfig, symmetricEncryptionMaterials);

            s3EncryptionClientFileModeSymmetricWrap =
                new AmazonS3EncryptionClientV4(fileConfig, symmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeAsymmetricWrap =
                new AmazonS3EncryptionClientV4(metadataConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientFileModeAsymmetricWrap =
                new AmazonS3EncryptionClientV4(fileConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeKMS = new AmazonS3EncryptionClientV4(metadataConfig, kmsEncryptionMaterials);

            s3EncryptionClientFileModeKMS = new AmazonS3EncryptionClientV4(fileConfig, kmsEncryptionMaterials);

            vanillaS3Client = new AmazonS3Client();
            
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
            vanillaS3Client.Dispose();
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
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, filePath, null, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.TestTransferUtilityCalculateMD5(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMS, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, filePath, null, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, filePath, null, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, filePath, null, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, SampleContentBytes,
                null, SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, null, SampleContentBytes, null,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, "", "",
                bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, "", "",
                bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrap, null, null, null, "",
                bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeSymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrap, null, null, null, "",
                bucketName, key);
            EncryptionTestsUtils.ValidateMetaData(vanillaS3Client, key, bucketName, 3);
            EncryptionTestsUtils.ValidateMetaDataIsReturnedAsIs(vanillaS3Client, s3EncryptionClientMetadataModeAsymmetricWrap, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrap, null, null, SampleContent,
                SampleContent, bucketName, key);
            EncryptionTestsUtils.ValidateInstructionFile(vanillaS3Client, key, bucketName, 3);
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
        public void PutGetNullContentContentUsingMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.TestPutGetCalculateMD5(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMS, null, null, null, "", bucketName);
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
        public void MultipartEncryptionTestMetadataModeKMS_WhenUploadPartIsNotInCorrectSequence()
        {
            //= ../specification/s3-encryption/client.md#optional-api-operations
            //= type=test
            //# - Each part MUST be encrypted in sequence.
            // Note: Parts has to in ascending order and skipping a part is fine by design 
            AssertExtensions.ExpectException(
                () => { EncryptionTestsUtils.MultipartEncryptionTest_WhenUploadPartIsNotInCorrectSequence(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMS, bucketName); },
                typeof(AmazonClientException), UploadPartsInIncorrectSequence);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () => { EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMS, bucketName); },
                typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.MultipartEncryptionTestCalculateMD5(s3EncryptionClientMetadataModeKMS, s3EncryptionClientMetadataModeKMS, bucketName);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetTamperedEncryptionContentUsingMetadataMode()
        {
            var key = $"key-{Guid.NewGuid()}";
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent, bucketName, key);

            // Tamper the content
            TamperCipherText(vanillaS3Client, bucketName, key);

            // Verify
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, null, s3EncryptionClientMetadataModeKMS, bucketName);
                },
                typeof(AmazonCryptoException), TamperCipherTextError);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetTamperedCekAlgUsingMetadataMode()
        {
            var key = $"key-{Guid.NewGuid()}";
            Regex errorMessage = new Regex(".*'x-amz-c' is invalid.*");
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent, bucketName, key);

            // Tamper the cek algorithm
            TamperCekAlg(vanillaS3Client, bucketName, key);
            
            // Verify
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent, s3EncryptionClientMetadataModeKMS, bucketName);
                },
                typeof(InvalidDataException), errorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetTamperedKeyCommitmentUsingMetadataMode()
        {
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
            
            var key = $"key-{Guid.NewGuid()}";

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent, bucketName, key);

            // Tamper the key commitment
            TamperKeyCommitment(vanillaS3Client, bucketName, key);
            
            // Verify
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent, s3EncryptionClientMetadataModeKMS, bucketName);
                },
                typeof(AmazonCryptoException), KeyCommitmentMismatchErrorMessage);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentWithTamperedEncryptionContextUsingMetadataModeKMS()
        {
            var key = $"key-{Guid.NewGuid()}";
            var errorRegex = new Regex(@"The service returned an error with Error Code InvalidCiphertextException .*");
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent, bucketName, key);
            
            // Tamper the encryption context
            TamperEncryptionContext(vanillaS3Client, bucketName, key);
            
            // Verify
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent, s3EncryptionClientMetadataModeKMS, bucketName);
                },
                typeof(InvalidCiphertextException), errorRegex);
        }
        
        [Fact]
        public void PutGetReplacedEncryptedKeyUsingMetadataMode()
        {
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST verify that the [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key commitment retrieved from the stored object's metadata.
            
            //= ../specification/s3-encryption/decryption.md#decrypting-with-commitment
            //= type=test
            //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the derived key commitment value and stored key commitment value do not match.
            
            var key = $"key-{Guid.NewGuid()}";
            // Put encrypted content
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMS, null, null, SampleContent, SampleContent, bucketName, key);

            // Replace encrypted key with AES 256 key from KMS GDK
            ReplaceEncryptedKey(vanillaS3Client, bucketName, key, kmsKeyID);
            
            // Verify
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent, s3EncryptionClientMetadataModeKMS, bucketName);
                },
                typeof(AmazonCryptoException), KeyCommitmentMismatchErrorMessage);
        }

        
        private static void TamperCipherText(AmazonS3Client vanillaS3Client, string bucketToTamper, string keyToTamper)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketToTamper,
                Key = keyToTamper
            };

            using (var getObjectResponse = vanillaS3Client.GetObject(getObjectRequest))
            {
                byte[] data;
                using (var memoryStream = new MemoryStream())
                {
                    getObjectResponse.ResponseStream.CopyTo(memoryStream);
                    data = memoryStream.ToArray();
                }

                // Flip the stored cipher text first byte and put back
                data[0] = (byte)~data[0];
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketToTamper,
                    Key = keyToTamper,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                vanillaS3Client.PutObject(putObjectRequest);
            }
        }


        private static void TamperCekAlg(AmazonS3Client vanillaS3Client, string bucketToTamper, string keyToTamper)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketToTamper,
                Key = keyToTamper
            };

            using (var getObjectResponse = vanillaS3Client.GetObject(getObjectRequest))
            {
                byte[] data;
                using (var memoryStream = new MemoryStream())
                {
                    getObjectResponse.ResponseStream.CopyTo(memoryStream);
                    data = memoryStream.ToArray();
                }
    
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketToTamper,
                    Key = keyToTamper,
                    InputStream = new MemoryStream(data),
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    putObjectRequest.Metadata.Add(metadataKey, 
                        metadataKey.Equals("x-amz-meta-x-amz-c") ? "Unsupported" : getObjectResponse.Metadata[metadataKey]);
                }

                vanillaS3Client.PutObject(putObjectRequest);
            }
        }

        private static void TamperEncryptionContext(AmazonS3Client vanillaS3Client, string bucketToTamper,
            string keyToTamper)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketToTamper,
                Key = keyToTamper
            };

            using (var getObjectResponse = vanillaS3Client.GetObject(getObjectRequest))
            {
                byte[] data;
                using (var memoryStream = new MemoryStream())
                {
                    getObjectResponse.ResponseStream.CopyTo(memoryStream);
                    data = memoryStream.ToArray();
                }
    
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketToTamper,
                    Key = keyToTamper,
                    InputStream = new MemoryStream(data)
                };
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-t"))
                    {
                        putObjectRequest.Metadata.Add("x-amz-meta-x-amz-t", "{\"Hello\":\"World\"}");
                        continue;
                    }

                    putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                }

                vanillaS3Client.PutObject(putObjectRequest);
            }
        }

        private static void TamperKeyCommitment(AmazonS3Client vanillaS3Client, string bucketNameToTamper, string keyToTamper)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketNameToTamper,
                Key = keyToTamper
            };

            using (var getObjectResponse = vanillaS3Client.GetObject(getObjectRequest))
            {
                byte[] data;
                using (var memoryStream = new MemoryStream())
                {
                    getObjectResponse.ResponseStream.CopyTo(memoryStream);
                    data = memoryStream.ToArray();
                }
    
                var putObjectRequest = new PutObjectRequest()
                {
                    BucketName = bucketNameToTamper,
                    Key = keyToTamper,
                    InputStream = new MemoryStream(data)
                };
    
                foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                {
                    if (metadataKey.Equals("x-amz-meta-x-amz-d"))
                    {
                        var keyCommitmentBase64 = getObjectResponse.Metadata[metadataKey];
                        var keyCommitmentBytes = Convert.FromBase64String(keyCommitmentBase64);
                        keyCommitmentBytes[0] ^= 1; // Flip first bit
                        putObjectRequest.Metadata.Add(metadataKey, Convert.ToBase64String(keyCommitmentBytes));
                    }
                    else
                    {
                        putObjectRequest.Metadata.Add(metadataKey, getObjectResponse.Metadata[metadataKey]);
                    }
                }

                vanillaS3Client.PutObject(putObjectRequest);
            }
        }

        private static void ReplaceEncryptedKey(AmazonS3Client vanillaS3Client, string bucketNameToTamper, string keyToTamper, string kmsKeyId)
        {
            var getObjectRequest = new GetObjectRequest()
            {
                BucketName = bucketNameToTamper,
                Key = keyToTamper
            };

            using (var getObjectResponse = vanillaS3Client.GetObject(getObjectRequest))
            {
                byte[] data;
                using (var memoryStream = new MemoryStream())
                {
                    getObjectResponse.ResponseStream.CopyTo(memoryStream);
                    data = memoryStream.ToArray();
                }

                using (var kmsClient = new Amazon.KeyManagementService.AmazonKeyManagementServiceClient())
                {
                    var generateDataKeyResponse = kmsClient.GenerateDataKey(new GenerateDataKeyRequest()
                    {
                        KeyId = kmsKeyId,
                        NumberOfBytes = 32,
                        EncryptionContext = new Dictionary<string, string> { ["aws:x-amz-cek-alg"] = "115" }
                    });

                    var putObjectRequest = new PutObjectRequest()
                    {
                        BucketName = bucketNameToTamper,
                        Key = keyToTamper,
                        InputStream = new MemoryStream(data)
                    };

                    foreach (var metadataKey in getObjectResponse.Metadata.Keys)
                    {
                        putObjectRequest.Metadata.Add(metadataKey, 
                            metadataKey.Equals("x-amz-meta-x-amz-3") 
                                ? Convert.ToBase64String(generateDataKeyResponse.CiphertextBlob.ToArray())
                                : getObjectResponse.Metadata[metadataKey]);
                    }

                    vanillaS3Client.PutObject(putObjectRequest);
                }
            }
        }
    }
}