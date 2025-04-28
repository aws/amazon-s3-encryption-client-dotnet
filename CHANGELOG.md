## Release 2025-04-28

### Amazon.Extensions.S3.Encryption (3.0.0)
* Updated the .NET SDK dependencies to the latest version GA 4.0.0

## Release 2025-04-01

### Amazon.Extensions.S3.Encryption (3.0.0-preview.5)
* Update AWS SDK to Preview 11

## Release 2025-03-03

### Amazon.Extensions.S3.Encryption (3.0.0-preview.4)
* Update .NET SDK dependencies to v4.0.0-preview.8

## Release 2024-01-23

### Amazon.Extensions.S3.Encryption (2.2.1)
* Improve exception message when instruction file is not found.

## Release 2024-10-24

### Amazon.Extensions.S3.Encryption (3.0.0-preview.3)
* Mark the assembly trimmable
* Enable Source Link

## Release 2024-10-16

### Amazon.Extensions.S3.Encryption (3.0.0-preview.2)
* Create traces using the SDK observability APIs for the S3 Encryption Encryption and Decryption pipeline handlers.

## Release 2024-10-10

### Amazon.Extensions.S3.Encryption (2.2.0)
* Create traces using the SDK observability APIs for the S3 Encryption Encryption and Decryption pipeline handlers.

## Release 2024-09-11

### Amazon.Extensions.S3.Encryption (3.0.0-preview.1)
* Dropped support for .NET Framework 3.5, updated .NET Framework 4.5 to .NET Framework 4.7.2 and added .NET 8 support
* Updated the .NET SDK dependencies to the latest version 4.0.0-preview.2
* Updated the `Portable.BouncyCastle` dependency to `BouncyCastle.Cryptography`

## Release 2024-09-03

### Amazon.Extensions.S3.Encryption (2.1.2)
* Fixed issue with AmazonS3EncryptionClientV2 and uploading multipart objects triggering a "HashStream does not support base streams that are not capable of reading or writing" error.

## Release 2024-04-20

### Amazon.Extensions.S3.Encryption (2.1.1)
* Update User-Agent string

## Release 2023-08-17

### Amazon.Extensions.S3.Encryption (2.1.0)
* Added KmsConfig to the client configuration, which allows users to configure the region, service URL, timeout, and other settings of the internal KMS client independently of the S3 client.

## Release 2023-02-13

### Amazon.Extensions.S3.Encryption (2.0.5)
* Fixed issue when AWS SES is configured to send encrypted emails to S3 bucket, and then email fails to be decrypted by Amazon.Extensions.S3.Encryption

## Release 2023-02-11

### Amazon.Extensions.S3.Encryption (2.0.4)
* Pull request [#32](https://github.com/aws/amazon-s3-encryption-client-dotnet/pull/32) Set KMS client config's timeout property. Thanks [1rjt](https://github.com/1rjt)

## Release 2021-08-11

### Amazon.Extensions.S3.Encryption (2.0.3)
* Update Portable.BouncyCastle dependency to version 1.8.10

## Release 2021-06-08

### Amazon.Extensions.S3.Encryption (2.0.2)
* Added ability to handle CalculateContentMD5Header flag for S3 uploads.

## Release 2021-04-14

### Amazon.Extensions.S3.Encryption (2.0.1)
* fix: update AWSSDK.Core, AWSSDK.S3, AWSSDK.KeyManagementService versions

## Release 2021-03-29

### Amazon.Extensions.S3.Encryption (2.0.0)
* Netstandard 1.3 support removed
* AWS SDK dependencies updated to v3.7

## Release 2021-01-14

### Amazon.Extensions.S3.Encryption (1.2.1)
* fix: update bouncy castle dependency versions

## Release 2020-10-09

### Amazon.Extensions.S3.Encryption (1.2.0)
* Fix issue creating KMS client.

## Release 2020-09-11

### Amazon.Extensions.S3.Encryption (1.1.0)
* Add ConcurrentDictionary to allow performing multipart uploads in multiple threads.

## Release 2020-08-07

### Amazon.Extensions.S3.Encryption (1.0.0)
* Initial release