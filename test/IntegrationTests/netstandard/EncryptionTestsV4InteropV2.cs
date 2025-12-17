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
using Amazon.Runtime.Internal.Util;
using Amazon.S3;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities;
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
            $" but commitment policy is set to {nameof(CommitmentPolicy.RequireEncryptRequireDecrypt)}." +
            " This commitment policy does not allow decryption of object encrypted with non key committing algorithm." +
            $" Retry with {nameof(CommitmentPolicy.RequireEncryptAllowDecrypt)} to encrypt with key committing algorithm" +
            " and allow decryption for object encrypted with non key committing algorithm.";
        
        private const string SampleContent = "Encryption Client Testing!";

        private static readonly byte[] SampleContentBytes = Encoding.UTF8.GetBytes(SampleContent);
        private string filePath = EncryptionTestsUtils.GetRandomFilePath(EncryptionTestsUtils.EncryptionPutObjectFilePrefix);
        private string bucketName;
        private string kmsKeyID;

        private AmazonS3CryptoConfigurationV2 metadataConfigV2;
        private AmazonS3CryptoConfigurationV2 fileConfigV2;
        
        private AmazonS3CryptoConfigurationV4 metadataConfigV4ForbidEncryptAllowDecrypt;
        private AmazonS3CryptoConfigurationV4 fileConfigV4ForbidEncryptAllowDecrypt;
        
        private AmazonS3CryptoConfigurationV4 metadataConfigV4RequireEncryptAllowDecrypt;
        private AmazonS3CryptoConfigurationV4 fileConfigV4RequireEncryptAllowDecrypt;
        
        private AmazonS3CryptoConfigurationV4 metadataConfigV4RequireEncryptDecrypt;
        private AmazonS3CryptoConfigurationV4 fileConfigV4RequireEncryptDecrypt;
        
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMSV4ForbidEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMSV4ForbidEncryptAllowDecrypt;
        
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt;
        
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt;
        private AmazonS3EncryptionClientV4 s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt;

        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeAsymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeSymmetricWrapV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientMetadataModeKMSV2;
        private AmazonS3EncryptionClientV2 s3EncryptionClientFileModeKMSV2;

        public EncryptionTestsV4InteropV2(KmsKeyIdProvider kmsKeyIdProvider) : base(kmsKeyIdProvider)
        {
            kmsKeyID = _kmsKeyIdProvider.GetKmsIdAsync().GetAwaiter().GetResult();

            var rsa = RSA.Create();
            var aes = Aes.Create();

            var asymmetricEncryptionMaterialsV4 = new EncryptionMaterialsV4(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV4 = new EncryptionMaterialsV4(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV4 = new EncryptionMaterialsV4(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());
            fileConfigV4ForbidEncryptAllowDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            metadataConfigV4ForbidEncryptAllowDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy,
                CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm);
            
            fileConfigV4RequireEncryptAllowDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            metadataConfigV4RequireEncryptAllowDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy,
                CommitmentPolicy.RequireEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
            
            fileConfigV4RequireEncryptDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment)
            {
                StorageMode = CryptoStorageMode.InstructionFile
            };
            metadataConfigV4RequireEncryptDecrypt = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy,
                CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);

            var asymmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(rsa, AsymmetricAlgorithmType.RsaOaepSha1);
            var symmetricEncryptionMaterialsV2 = new EncryptionMaterialsV2(aes, SymmetricAlgorithmType.AesGcm);
            var kmsEncryptionMaterialsV2 = new EncryptionMaterialsV2(kmsKeyID, KmsType.KmsContext, new Dictionary<string, string>());

            metadataConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.ObjectMetadata,
            };

            fileConfigV2 = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy, CommitmentPolicy.ForbidEncryptAllowDecrypt, ContentEncryptionAlgorithm.AesGcm)
            {
                StorageMode = CryptoStorageMode.InstructionFile,
            };
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptDecrypt, kmsEncryptionMaterialsV4);
            s3EncryptionClientFileModeKMSV4RequireEncryptDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptDecrypt, kmsEncryptionMaterialsV4);
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptAllowDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptAllowDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptAllowDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptAllowDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4RequireEncryptAllowDecrypt, kmsEncryptionMaterialsV4);
            s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4RequireEncryptAllowDecrypt, kmsEncryptionMaterialsV4);
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4ForbidEncryptAllowDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4ForbidEncryptAllowDecrypt, asymmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4ForbidEncryptAllowDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4ForbidEncryptAllowDecrypt, symmetricEncryptionMaterialsV4);
            s3EncryptionClientMetadataModeKMSV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(metadataConfigV4ForbidEncryptAllowDecrypt, kmsEncryptionMaterialsV4);
            s3EncryptionClientFileModeKMSV4ForbidEncryptAllowDecrypt = new AmazonS3EncryptionClientV4(fileConfigV4ForbidEncryptAllowDecrypt, kmsEncryptionMaterialsV4);

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
            bucketName = EncryptionTestsUtils.CallAsyncTask(UtilityMethods.CreateBucketAsync(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt));
        }

        protected override void Dispose(bool disposing)
        {
            EncryptionTestsUtils.CallAsyncTask(UtilityMethods.DeleteBucketWithObjectsAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName));
            
            s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt.Dispose();
            s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt.Dispose();
            s3EncryptionClientMetadataModeKMSV4ForbidEncryptAllowDecrypt.Dispose();
            s3EncryptionClientFileModeKMSV4ForbidEncryptAllowDecrypt.Dispose();
            
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
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
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
            
            // This is tested by encrypting with non-key commitment and trying to decrypt with key commitment
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetFileUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    filePath, null, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }
        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName).ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, "", "", bucketName).ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName).ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, "", "", bucketName).ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", "", bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV2,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2,
                    null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV2,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeAsymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingInstructionFileModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV2,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            // This is tested with error message thrown on decryption.
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt,
                    s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeSymmetricWrapV4ForbidEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2,
                    null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetFileUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    filePath, null, null, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetStreamUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, SampleContentBytes, null, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetStreamUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    null, SampleContentBytes, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => { return EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    null, SampleContentBytes, null, SampleContent, bucketName); });
            }, InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, null, SampleContent, SampleContent, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetZeroLengthContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    filePath, null, null, SampleContent, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, null, "", "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void PutGetNullContentContentUsingMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV2,
                    s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt,
                    filePath, null, null, "", bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2,
                null, null, null, "", bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void PutGetContentUsingInstructionFileModeKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt,
                    null, null, SampleContent, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.TestPutGetAsync(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2,
                    null, null, SampleContent, SampleContent, bucketName));
            }, InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync( 
                    s3EncryptionClientMetadataModeAsymmetricWrapV2, s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV2, 
                    s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptDecrypt, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileAsymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV2, s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV2, 
                    s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptDecrypt, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeAsymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestInstructionFileSymmetricWrap()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV2, s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptDecrypt, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);
            
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeSymmetricWrapV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeSymmetricWrapV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public async void MultipartEncryptionTestMetadataModeKMS()
        {
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //= type=test
            //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // This citation is proved by encrypting with V2 client and decrypting with V4 client with RequireEncryptAllowDecrypt
            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, bucketName)
                .ConfigureAwait(false);
            
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
            AssertExtensions.ExpectException<ArgumentException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV2, s3EncryptionClientMetadataModeKMSV4RequireEncryptDecrypt, bucketName));
            }, NonCommittingAlgAndCommittingPolicyErrorMessage);

            await EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientMetadataModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientMetadataModeKMSV2, bucketName)
                .ConfigureAwait(false);
        }

        [Fact]
        [Trait(CategoryAttribute,"S3")]
        public void MultipartEncryptionTestInstructionFileKMS()
        {
            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV2, s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, bucketName));
            }, InstructionAndKMSErrorMessageV2);

            AssertExtensions.ExpectException(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.MultipartEncryptionTestAsync(s3EncryptionClientFileModeKMSV4RequireEncryptAllowDecrypt, s3EncryptionClientFileModeKMSV2, bucketName));
            }, InstructionAndKMSErrorMessageV4);
        }

        [Fact]
        [Trait(CategoryAttribute, "S3")]
        public void TestRangeGetIsDisabled()
        {
            AssertExtensions.ExpectException<NotSupportedException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.AttemptRangeGet(s3EncryptionClientFileModeAsymmetricWrapV4RequireEncryptAllowDecrypt, bucketName));
            }, EncryptionTestsUtils.RangeGetNotSupportedMessage);

            AssertExtensions.ExpectException<NotSupportedException>(() =>
            {
                AsyncHelpers.RunSync(() => EncryptionTestsUtils.AttemptRangeGet(s3EncryptionClientFileModeAsymmetricWrapV2, bucketName));
            }, EncryptionTestsUtils.RangeGetNotSupportedMessage);
        }
    }
}
