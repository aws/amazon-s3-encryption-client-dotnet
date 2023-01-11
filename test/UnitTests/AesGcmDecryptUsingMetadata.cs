using System.Collections.Generic;
using System.Text;
using Amazon.Extensions.S3.Encryption.Internal;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3.Model;
using Moq;
using System.IO;
using Xunit.Extensions;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AesGcmDecryptUsingMetadata
    {
        /* Metadata extracted from an encrypted S3 object sample using AWS SES */
        private static readonly byte[] DecryptedEnvelopeKeyKMS = { 52, 5, 73, 94, 237, 126, 210, 67, 26, 221, 182, 9, 236, 225, 197, 184, 147, 117, 60, 119, 141, 201, 21, 19, 2, 178, 62, 22, 120, 102, 137, 45 };
        private static readonly string[] MetadataDictionaryKeys = { "x-amz-meta-x-amz-tag-len", "x-amz-meta-x-amz-unencrypted-content-length", "x-amz-meta-x-amz-wrap-alg",
                "x-amz-meta-x-amz-matdesc" , "x-amz-meta-x-amz-key-v2" , "x-amz-meta-x-amz-cek-alg", "x-amz-meta-x-amz-iv" };
        private static readonly string[] MetadataDictionaryValues = { "128", "3946", "kms", "{\"aws:ses:message-id\":\"lhne4tbq09c867b1ko1f3ho4fqfidcatruo26781\",\"aws:ses:rule-name\":\"encrypt-to-s3\",\"aws:ses:source-account\":\"{AWS_ACCOUNT_ID}\",\"kms_cmk_id\":\"arn:aws:kms:{AWS_ACCOUNT_ID}:{AWS_ACCOUNT_ID}:alias/aws/ses\"}",
            "AQIDAHgN94fUlYO17HEeDorBZENwiXuQ3swljPjtZVKT/lVftAHJVBJhXNH02aAWuPsxxBo5AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMvq8jOYujNpL+coHxAgEQgDsRyJ3hFidKl5hw208WxBcNPCnlFmHyQ36HEewuORCoqGIor4uuhe3mcmVdGv2e5qob3Ju/C4hC3Ekpvg==",
            "AES/GCM/NoPadding", "NUhrJ+0LoGyof/dj" };
        private static readonly string KmsKeyId = "730b1bf4-9483-4834-b75e-8174ad092192";

        [Theory]
        [InlineData(SecurityProfile.V2)]
        public void DecryptWithoutEncryptionContext_SecurityProfileV2(SecurityProfile securityProfile)
        {
            var encryptionMaterialsV2 = new EncryptionMaterialsV2(KmsKeyId, Primitives.KmsType.KmsContext, new Dictionary<string, string>());
            var amazonS3EncryptionClientV2 = new AmazonS3EncryptionClientV2(new AmazonS3CryptoConfigurationV2(securityProfile), encryptionMaterialsV2);
            var mockSetupDecryptionHandlerV2 = new Mock<SetupDecryptionHandlerV2>(amazonS3EncryptionClientV2);

            mockSetupDecryptionHandlerV2.CallBase = true;

            var mockObjectResponse = new Mock<GetObjectResponse>();
            for (int i = 0; i < MetadataDictionaryKeys.Length; i++)
            {
                mockObjectResponse.Object.Metadata.Add(MetadataDictionaryKeys[i], MetadataDictionaryValues[i]);
            }

            Assert.Throws<AmazonCryptoException>(() =>
            {
                Utils.RunInstanceMethod(typeof(SetupDecryptionHandlerV2), "DecryptObjectUsingMetadata", mockSetupDecryptionHandlerV2.Object, new object[] { mockObjectResponse.Object, DecryptedEnvelopeKeyKMS });
            });
        }

        [Theory]
        [InlineData(SecurityProfile.V2AndLegacy)]
        public void DecryptWithoutEncryptionContext_V2AndLegacy(SecurityProfile securityProfile)
        {
            var encryptionMaterialsV2 = new EncryptionMaterialsV2(KmsKeyId, Primitives.KmsType.KmsContext, new Dictionary<string, string>());
            var amazonS3EncryptionClientV2 = new AmazonS3EncryptionClientV2(new AmazonS3CryptoConfigurationV2(securityProfile), encryptionMaterialsV2);
            var mockSetupDecryptionHandlerV2 = new Mock<SetupDecryptionHandlerV2>(amazonS3EncryptionClientV2);

            mockSetupDecryptionHandlerV2.CallBase = true;

            var mockObjectResponse = new Mock<GetObjectResponse>();
            mockObjectResponse.Object.ResponseStream = new MemoryStream(Encoding.UTF8.GetBytes(""));
            for (int i = 0; i < MetadataDictionaryKeys.Length; i++)
            {
                mockObjectResponse.Object.Metadata.Add(MetadataDictionaryKeys[i], MetadataDictionaryValues[i]);
            }

            Utils.RunInstanceMethod(typeof(SetupDecryptionHandlerV2), "DecryptObjectUsingMetadata", mockSetupDecryptionHandlerV2.Object, new object[] { mockObjectResponse.Object, DecryptedEnvelopeKeyKMS });

            Assert.True(mockObjectResponse.Object.ResponseStream.GetType() == typeof(AesGcmDecryptStream));
        }

    }
}

