---
_layout: landing
---

# Amazon S3 Encryption Client for .NET

## Overview

These are the API docs for the Amazon S3 Encryption client for .NET. There exist two (2) clients in this product:
* AmazonS3EncryptionClientV2
* AmazonS3EncryptionClientV4

The AmazonS3EncryptionClientV2 has an identical API to the AmazonS3EncryptionClientV4 that is in the AWS SDK for .NET. The main difference is
that AmazonS3EncryptionClientV2 can only decrypt message with content encryption AesGcmWithCommitment, while AmazonS3EncryptionClientV4 can encrypt or decrypt
message with content encryption AesGcmWithCommitment. It is recommended to use AesGcmWithCommitment instead of AesGcm without key commitment because key commitment 
prevents attackers from crafting ciphertexts that decrypt to different plaintexts under different keys, protecting against key substitution attacks when on instruction file mode.

## How to use the AmazonS3EncryptionClientV4 client

The AmazonS3EncryptionClientV4 supports the following encryption methods for encrypting DEKs (Data encryption keys):

* AWS supplied KEK (key encryption key):
  * AWS KMS + Context
* User supplied KEK:
  * RSA-OAEP-SHA1
  * AES-GCM

Object content is encrypted using committing AES-GCM (default) with generated DEKs which are stored in the S3 object metadata or in a separate instruction file (as configured).


### Data Key Encryption

#### AWS KMS + Context

To use "AWS KMS + Context", you must supply an EncryptionMaterialsV4 instance with the following information:

* A KMS key id
  * This id will be used in decryption as well. If the id specified is not the key used to encrypt the object, decryption will fail.
* The type of KMS encryption to use (KmsType.KmsContext)
* Encryption context in the form of key-value pairs. <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context>
  * Encryption context will always be supplied to KMS. AWS data will be merged in. You can supply an empty dictionary, but supplying additional data is encouraged.

```csharp
var encryptionContext = new Dictionary<string, string>();
var encryptionMaterial =
    new EncryptionMaterialsV4("1234abcd-12ab-34cd-56ef-1234567890ab", KmsType.KmsContext, encryptionContext);
var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
var encryptionClient = new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
```

#### RSA-OAEP-SHA1

To use "RSA-OAEP-SHA1", you must supply an EncryptionMaterialsV4 instance with the following information:

* A RSA instance containing the encryption materials.
* Which algorithm to use (AsymmetricAlgorithmType.RsaOaepSha1)

```csharp
var asymmetricAlgorithm = RSA.Create();
var encryptionMaterial = new EncryptionMaterialsV4(asymmetricAlgorithm, AsymmetricAlgorithmType.RsaOaepSha1);
var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
var encryptionClient = new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
```

#### AES-GCM

To use "AES-GCM", you must supply an EncryptionMaterialsV4 instance with the following information:

* An Aes instance containing the encryption materials.
* Which algorithm to use (SymmetricAlgorithmType.AesGcm)

```csharp
var symmetricAlgorithm = Aes.Create();
var encryptionMaterial = new EncryptionMaterialsV4(symmetricAlgorithm, SymmetricAlgorithmType.AesGcm);
var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4, CommitmentPolicy.RequireEncryptRequireDecrypt, ContentEncryptionAlgorithm.AesGcmWithCommitment);
var encryptionClient = new AmazonS3EncryptionClientV4(configuration, encryptionMaterial);
```

### CommitmentPolicy and ContentEncryptionAlgorithm

Starting with Amazon S3 Encryption Client for .NET V4, you can encrypt objects with AES-GCM with key commitment (default for V4), which protects your data against key substitution attacks. To help you migrate from AES-GCM to AES-GCM with key commitment, this version includes three commitment policies.

For more information, see [S3 Encryption Client Migration (V2 to V4)](https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/s3-encryption-migration-v2-v4.html). 

* ForbidEncryptAllowDecrypt: 
  * With ForbidEncryptAllowDecrypt CommitmentPolicy, the client continues to encrypt objects without key commitment and can decrypt both non-key-committing objects and key-committing objects encrypted with AES GCM with commitment.
  * Because this policy encrypts with AES-GCM without key commitment, it does not enforce commitment and may allow keys in Instruction Files to be tampered with which does not protect against key substitution attacks.

* RequireEncryptAllowDecrypt
  * With RequireEncryptAllowDecrypt CommitmentPolicy, the client starts encrypting objects with key commitment (AES-GCM with key commitment) and can still decrypt objects encrypted without key commitment.
  * This policy protects newly encrypted objects against key substitution attacks while maintaining backward compatibility for decryption.

* RequireEncryptRequireDecrypt (default for V4)
  * With RequireEncryptRequireDecrypt CommitmentPolicy, the client will no longer decrypt objects encrypted without key commitment (AES-GCM without key commitment) and cannot decrypt objects encrypted without key commitment.
  * This policy fully enforces key commitment and protects against key substitution attacks.
  
### Storage Mode

You can specify a storage mode for the encrypted data key and associated metadata needed for decryption of an object:

* ObjectMetadata (default)
  * Stores the data with the encrypted object as S3 metadata
* InstructionFile
  * Stores the data in a separate S3 object

This can be set on the AmazonS3CryptoConfigurationV4 instance:

```csharp
var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4)
{
    StorageMode.InstructionFile
}
```

### Security Profile

A security profile setting needs to be passed to the constructor of the AmazonS3CryptoConfigurationV4 instance, either:

* V4
* V4AndLegacy

Unless you are migrating existing applications from legacy content encryption message format (message encrypted with AmazonS3EncryptionClient which uses AES CBC), use V4. If you need legacy mode:

```csharp
var configuration = new AmazonS3CryptoConfigurationV4(SecurityProfile.V4AndLegacy);
```

### Multipart Uploads

The AmazonS3EncryptionClientV4 extends the base AmazonS3Client. You can use multipart upload using the same APIs: <https://docs.aws.amazon.com/AmazonS3/latest/dev/LLuploadFileDotNet.html>

### Transfer Utility Integration

The AmazonS3EncryptionClientV4 extends the base AmazonS3Client. You can use the TransferUtility just as you would using the base AmazonS3Client: <https://docs.aws.amazon.com/AmazonS3/latest/dev/HLuploadFileDotNet.html>