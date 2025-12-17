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
using Amazon.Runtime;
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using Amazon.S3.Util;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public class EncryptionTestsV4InteropV2 : TestBase<AmazonS3Client>
    {
        private const string InstructionAndKMSErrorMessageV2 = "AmazonS3EncryptionClientV2 only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";
        private const string InstructionAndKMSErrorMessageV4 = "AmazonS3EncryptionClientV4 only supports KMS key wrapping in metadata storage mode. " +
                                                               "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.";

        private const string NonCommittingAlgAndCommittingPolicyErrorMessage =
            "The requested object is encrypted with non key committing algorithm" +
            " but commitment policy is set to RequireEncryptRequireDecrypt." +
            " This commitment policy does not allow decryption of object encrypted with non key committing algorithm." +
            " Retry with RequireEncryptAllowDecrypt to encrypt with key committing algorithm" +
            " and allow decryption for object encrypted with non key committing algorithm.";

        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);

        private string filePath =
            EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);

        private static string bucketName;
        private static string kmsKeyID;

        private readonly AmazonS3CryptoConfigurationV2 metadataConfigV2;
        private readonly AmazonS3CryptoConfigurationV2 fileConfigV2;
        
        private AmazonS3CryptoConfigurationV4 metadataConfigV4;
        private AmazonS3CryptoConfigurationV4 fileConfigV4;
        
        private AmazonS3CryptoConfigurationV4 metadataConfigV4RequireEncryptDecrypt;
        private AmazonS3CryptoConfigurationV4 fileConfigV4RequireEncryptDecrypt;
        
        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt;
        private static AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt;
        
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt;

        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private static AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTestsV4InteropV2() : base(KmsKeyIdProvider.Instance)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsId();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterialsV4 = new EncryptionMaterialsV4(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV4 = new EncryptionMaterialsV4(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV4 = new EncryptionMaterialsV4(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            fileConfigV4 = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            metadataConfigV4 = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4,
                CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
            
            fileConfigV4RequireEncryptDecrypt = new AmazonS3CryptoConfigurationV4
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            metadataConfigV4RequireEncryptDecrypt = new AmazonS3CryptoConfigurationV4();

            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV2 =
                new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            
            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata,
            };
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, kmsEncryptionMaterialsV4);
            s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, kmsEncryptionMaterialsV4);
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4, symmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4, symmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4, kmsEncryptionMaterialsV4);
            s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4, kmsEncryptionMaterialsV4);

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

            bucketName = S3TestUtils.CreateBucketWithWait(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt);
        }

        protected override void Dispose(bool disposing)
        {
            AmazonS3Util.DeleteS3BucketWithObjects(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt.Dispose();
            s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt.Dispose();
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt.Dispose();
            s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt.Dispose();
            s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt.Dispose();

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
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientFileModeKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV2,
                        s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                        s3EncryptionClientFileModeKMSV2, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt,
                        s3EncryptionClientFileModeKMSV2, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestTransferUtilityS3EncryptionClientMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV2,
                s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, bucketName);

            EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeKMSV2, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestTransferUtility(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeSymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName);
        }


        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeSymmetricWrapV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    null, null, "", "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, null, "", "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    null, null, null, "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, null, null, "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, SampleContentBytes, null, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    null, SampleContentBytes, null, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, null, SampleContent, SampleContent, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    null, null, "", "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null,
                null, "", "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetNullContentContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    null, null, null, "", bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.TestPutGet(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, "", bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
            
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.TestPutGet(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt,
                    null, null, SampleContent, SampleContent, bucketName);
            }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV2, 
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV2,
                s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV2,
                s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV2,
                s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                s3EncryptionClientFileModeSymmetricWrapV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV2,
                s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, bucketName);
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
            // The error message proves that the check occurred after GetObject but before Decryption
            // assuming no refactor adds the same error message to another throw code point.
            
            //= ../specification/s3-encryption/decryption.md#key-commitment
            //= type=test
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite associated with the object does not support key commitment, then the S3EC MUST throw an exception.

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            AssertExtensions.ExpectException(() =>
            {
                EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt, bucketName);
            }, typeof(ArgumentException), NonCommittingAlgAndCommittingPolicyErrorMessage);

            EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                s3EncryptionClientMetadataModeKMSV2, bucketName);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV2,
                        s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                        s3EncryptionClientFileModeKMSV2, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
            
            AssertExtensions.ExpectException(
                () =>
                {
                    EncryptionTestsUtils.MultipartEncryptionTest(s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt,
                        s3EncryptionClientFileModeKMSV2, bucketName);
                }, typeof(AmazonClientException), InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestRangeGetIsDisabled()
        {
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName);
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName);
            EncryptionTestsUtils.TestRangeGetDisabled(s3EncryptionClientFileModeAsymmetricWrapV2, bucketName);
        }
    }
}