# Change log

## 2.2.0 (2024-10-10)
 - Create traces using the SDK observability APIs for the S3 Encryption Encryption and Decryption pipeline handlers.

## 2.1.2 (2024-09-03)
 - Fixed issue with AmazonS3EncryptionClientV2 and uploading multipart objects triggering a "HashStream does not support base streams that are not capable of reading or writing" error.

## 2.1.1 (2024-04-20)
 - Update User-Agent string

## 2.1.0 (2023-08-17)
- Added KmsConfig to the client configuration, which allows users to configure the region, service URL, timeout, and other settings of the internal KMS client independently of the S3 client.

## 2.0.5 (2023-02-13)
- Fixed issue when AWS SES is configured to send encrypted emails to S3 bucket, and then email fails to be decrypted by Amazon.Extensions.S3.Encryption

## 2.0.4 (2023-02-11)
- Pull request [#32](https://github.com/aws/amazon-s3-encryption-client-dotnet/pull/32) Set KMS client config's timeout property. Thanks [1rjt](https://github.com/1rjt)

## 2.0.3 (2021-08-11)
- Update Portable.BouncyCastle dependency to version 1.8.10

## 2.0.2 (2021-06-08)
- Added ability to handle CalculateContentMD5Header flag for S3 uploads.

## 2.0.1 (2021-04-14)
- fix: update AWSSDK.Core, AWSSDK.S3, AWSSDK.KeyManagementService versions

## 2.0.0 (2021-03-29)
- Netstandard 1.3 support removed
- AWS SDK dependencies updated to v3.7

## 1.2.1 (2021-01-14)
- fix: update bouncy castle dependency versions

## 1.2.0 (2020-10-09)
- Fix issue creating KMS client.

## 1.1.0 (2020-09-11)
- Add ConcurrentDictionary to allow performing multipart uploads in multiple threads.

## 1.0.0 (2020-08-07)
- Initial release