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
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Util;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Xunit;

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
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSWithEC;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSWithEC;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSWithoutEC;
        
        private AmazonS3Client s3Client;

        public EncryptionTestsV2() : base(KmsKeyIdProvider.Instance)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsId();

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

            s3EncryptionClientMetadataModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, symmetricEncryptionMaterials);

            s3EncryptionClientFileModeSymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, symmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(metadataConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientFileModeAsymmetricWrap =
                new AmazonS3EncryptionClientV2(fileConfig, asymmetricEncryptionMaterials);

            s3EncryptionClientMetadataModeKMSWithEC = new AmazonS3EncryptionClientV2(metadataConfig, kmsEncryptionMaterialsWithEC);
            s3EncryptionClientMetadataModeKMSWithoutEC = new AmazonS3EncryptionClientV2(metadataConfig, kmsEncryptionMaterialsWithoutEC);
            s3EncryptionClientFileModeKMSWithEC = new AmazonS3EncryptionClientV2(fileConfig, kmsEncryptionMaterialsWithEC);
            
            s3Client = new AmazonS3Client();

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
            s3EncryptionClientMetadataModeKMSWithEC.Dispose();
            s3EncryptionClientMetadataModeKMSWithoutEC.Dispose();
            s3EncryptionClientFileModeKMSWithEC.Dispose();
            s3Client.Dispose();
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
                () => { EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSWithEC, bucketName); },
                typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSWithEC, bucketName);
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
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.TestTransferUtilityCalculateMD5(s3EncryptionClientMetadataModeKMSWithEC, s3EncryptionClientMetadataModeKMSWithEC, bucketName);
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
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSWithEC, filePath, null, null, SampleContent,
                        bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithEC, null, SampleContentBytes, null,
                SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSWithEC, null, SampleContentBytes, null,
                        SampleContent, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithEC, null, null, SampleContent, SampleContent,
                bucketName);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingKMSWithSameRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            var encryptionContext = new Dictionary<string, string>(TestConstants.RequestEC1);
            var expectedEncryptionContext = encryptionContext;

            expectedEncryptionContext.Add(TestConstants.XAmzEncryptionContextCekAlg, TestConstants.XAmzAesGcmCekAlgValue);
            
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                SampleContent, SampleContent, bucketName, key, TestConstants.RequestEC1, TestConstants.RequestEC1);
            
            // This proves the material description in S3 is what we expect.
            EncryptionTestsUtils.TestGet(
                key, SampleContent, s3Client, bucketName,
                TestConstants.RequestEC1, false, true, expectedEncryptionContext);
            
            EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(
                key, SampleContent, s3Client, bucketName,
                TestConstants.RequestEC1, false, true, expectedEncryptionContext));
            
            // This proves the EC we are sending to KMS is actually the EC we expect without using S3EC at all.
            EncryptionTestsUtils.DecryptDataKeyWithoutS3EC(key, s3Client, bucketName,
                TestConstants.XAmzKeyV2, expectedEncryptionContext, TestConstants.RequestEC1);
            
            // This is expected to fail as TestConstants.RequestEC1 does not have reserved key and mismatch is expected.
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.DecryptDataKeyWithoutS3EC(key, s3Client, bucketName,
                        TestConstants.XAmzKeyV2, TestConstants.RequestEC1, TestConstants.RequestEC1);
                }, typeof(InvalidCiphertextException));
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingKMSWithDifferentRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";

            EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeKMSWithoutEC,
                null, null, SampleContent, bucketName, key, TestConstants.RequestEC1);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent,
                        s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.RequestEC2);
                }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(key, SampleContent,
                        s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.RequestEC2));
                }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingKMSWithNoECAtAll()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                SampleContent, SampleContent, bucketName);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutContentUsingKMSWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeKMSWithEC, 
                        null, null, SampleContent, bucketName, key, TestConstants.RequestEC1);
                }, typeof(ArgumentException), TestConstants.MultipleECErrorMesage);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeKMSWithEC, 
                        null, null, SampleContent, bucketName, key, TestConstants.RequestEC1);
                }, typeof(ArgumentException), TestConstants.MultipleECErrorMesage);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingKMSWithReservedKeyInRequestEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(
                        s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                        SampleContent, bucketName, key, TestConstants.EncryptionContextWithReservedKey));
                }, typeof(ArgumentException), TestConstants.ReservedKeyInECErrorMessage);
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPut(
                        s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                        SampleContent, bucketName, key, TestConstants.EncryptionContextWithReservedKey);
                }, typeof(ArgumentException), TestConstants.ReservedKeyInECErrorMessage);
            
            // The version of encrypted object can only be determined after getting object from S3. 
            // So, this is a dummy put to test get object fails.
            EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeKMSWithoutEC, null, null,
                    SampleContent, bucketName, key);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestGet(key, SampleContent, 
                        s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.EncryptionContextWithReservedKey);
                }, typeof(ArgumentException), TestConstants.ReservedKeyInECErrorMessage);
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestGetAsync(key, SampleContent, 
                        s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.EncryptionContextWithReservedKey));
                }, typeof(ArgumentException), TestConstants.ReservedKeyInECErrorMessage);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMSWithSameRequestEC()
        {
            EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSWithoutEC, 
                s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1));
            
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSWithoutEC, 
                s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, TestConstants.RequestEC1, TestConstants.RequestEC1);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMSWithDifferentRequestEC()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSWithoutEC, bucketName, 
                        TestConstants.RequestEC1, TestConstants.RequestEC2);
                }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSWithoutEC, s3EncryptionClientMetadataModeKMSWithoutEC, 
                        bucketName, TestConstants.RequestEC1, TestConstants.RequestEC2));
                }, typeof(AmazonS3EncryptionClientException), TestConstants.ECNotMatched);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingAsymmetricWrapWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeAsymmetricWrap, 
                        null, null, SampleContent, bucketName, key, TestConstants.RequestEC1));
                }, typeof(ArgumentException), TestConstants.ECNotSupported);
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeAsymmetricWrap, 
                        null, null, SampleContent, bucketName, key, TestConstants.RequestEC1);
                }, typeof(ArgumentException), TestConstants.ECNotSupported);
        }
        
        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingSymmetricWrapWithRequestAndClientEC()
        {
            var key = $"key-{Guid.NewGuid()}";
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.WaitForAsyncTask(EncryptionTestsUtils.TestPutAsync(s3EncryptionClientMetadataModeSymmetricWrap, 
                        null, null, SampleContent, bucketName, key, TestConstants.RequestEC1));
                }, typeof(ArgumentException), TestConstants.ECNotSupported);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPut(s3EncryptionClientMetadataModeSymmetricWrap, null, null, 
                        SampleContent, bucketName, key, TestConstants.RequestEC1);
                }, typeof(ArgumentException), TestConstants.ECNotSupported);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithEC, null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSWithEC, null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSWithEC, null, null, SampleContent,
                        SampleContent, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.TestPutGetCalculateMD5(s3EncryptionClientMetadataModeKMSWithEC, s3EncryptionClientMetadataModeKMSWithEC, null, null, null, "", bucketName);
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
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSWithEC, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () => { EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSWithEC, bucketName); },
                typeof(AmazonClientException), InstructionAndKMSErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMSCalculateMD5()
        {
            EncryptionTestsUtils.MultipartEncryptionTestCalculateMD5(s3EncryptionClientMetadataModeKMSWithEC, s3EncryptionClientMetadataModeKMSWithEC, bucketName);
        }
    }
}