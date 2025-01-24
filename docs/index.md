---
_layout: landing
---

# Amazon S3 Encryption Client for .NET

## Overview

These are the API docs for the Amazon S3 Encryption client for .NET. There exist two (2) clients in this product:
* AmazonS3EncryptionClient
* AmazonS3EncryptionClientV2

The AmazonS3EncryptionClient has an identical API to the obsolete client that is in the AWS SDK for .NET. The main difference is
that this client can also decrypt AmazonS3EncryptionClientV2 encrypted objects.

## How to use the AmazonS3EncryptionClientV2 client

The AmazonS3EncryptionClientV2 supports the following encryption methods for encrypting DEKs (Data encryption keys):

* AWS supplied KEK (key encryption key):
  * AWS KMS + Context
* User supplied KEK:
  * RSA-OAEP-SHA1
  * AES-GCM

Object content is encrypted using AES-GCM with generated DEKs which are stored in the S3 object metadata or in a separate instruction file (as configured).

### Data Key Encryption

#### AWS KMS + Context

To use "AWS KMS + Context", you must supply an EncryptionMaterialsV2 instance with the following information:

* A KMS key id
  * This id will be used in decryption as well. If the id specified is not the key used to encrypt the object, decryption will fail.
* The type of KMS encryption to use (KmsType.KmsContext)
* Encryption context in the form of key-value pairs. <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context>
  * Encryption context will always be supplied to KMS. AWS data will be merged in. You can supply an empty dictionary, but supplying additional data is encouraged.

```csharp
var encryptionContext = new Dictionary<string, string>();
var encryptionMaterial =
    new EncryptionMaterialsV2("1234abcd-12ab-34cd-56ef-1234567890ab", KmsType.KmsContext, encryptionContext);
var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
```

#### RSA-OAEP-SHA1

To use "RSA-OAEP-SHA1", you must supply an EncryptionMaterialsV2 instance with the following information:

* A RSA instance containing the encryption materials.
* Which algorithm to use (AsymmetricAlgorithmType.RsaOaepSha1)

```csharp
var asymmetricAlgorithm = RSA.Create();
var encryptionMaterial = new EncryptionMaterialsV2(asymmetricAlgorithm, AsymmetricAlgorithmType.RsaOaepSha1);
var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
```

#### AES-GCM

To use "AES-GCM", you must supply an EncryptionMaterialsV2 instance with the following information:

* An Aes instance containing the encryption materials.
* Which algorithm to use (SymmetricAlgorithmType.AesGcm)

```csharp
var symmetricAlgorithm = Aes.Create();
var encryptionMaterial = new EncryptionMaterialsV2(symmetricAlgorithm, SymmetricAlgorithmType.AesGcm);
var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2);
var encryptionClient = new AmazonS3EncryptionClientV2(configuration, encryptionMaterial);
```

### Storage Mode

You can specify a storage mode for the encrypted data key and associated metadata needed for decryption of an object:

* ObjectMetadata (default)
  * Stores the data with the encrypted object as S3 metadata
* InstructionFile
  * Stores the data in a separate S3 object

This can be set on the AmazonS3CryptoConfigurationV2 instance:

```csharp
var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2)
{
    StorageMode.InstructionFile
}
```

### Security Profile

A security profile setting needs to be passed to the constructor of the AmazonS3CryptoConfigurationV2 instance, either:

* V2
* V2AndLegacy

Unless you are migrating existing applications, use V2. If you need leagcy mode:

```csharp
var configuration = new AmazonS3CryptoConfigurationV2(SecurityProfile.V2AndLegacy);
```

### Multipart Uploads

The AmazonS3EncryptionClientV2 extends the base AmazonS3Client. You can use multipart upload using the same APIs: <https://docs.aws.amazon.com/AmazonS3/latest/dev/LLuploadFileDotNet.html>

### Transfer Utility Integration

The AmazonS3EncryptionClientV2 extends the base AmazonS3Client. You can use the TransferUtility just as you would using the base AmazonS3Client: <https://docs.aws.amazon.com/AmazonS3/latest/dev/HLuploadFileDotNet.html>