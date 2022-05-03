![.NET on AWS Banner](./logo.png ".NET on AWS")

## Amazon S3 Encryption Client for .NET

[![nuget](https://img.shields.io/nuget/v/Amazon.Extensions.S3.Encryption.svg)](https://www.nuget.org/packages/Amazon.Extensions.S3.Encryption/)

[The Amazon S3 Encryption Client for .NET](https://www.nuget.org/packages/Amazon.Extensions.S3.Encryption/) provides an easy-to-use Amazon S3 encryption client that allows you to secure your sensitive data before you send it to Amazon S3. The AmazonS3EncryptionClientV2 client automatically encrypts data on the client when uploading to Amazon S3, and automatically decrypts it when data is retrieved. You can use the client just like the regular S3 client, working with things like multipart uploads and the Transfer Utility with no additional code changes required besides swapping out the client used.

The AmazonS3EncryptionClientV2 supports the following encryption methods for encrypting DEKs (Data encryption keys):

* AWS supplied KEK (key encryption key):
  * AWS KMS + Context
* User supplied KEK:
  * RSA-OAEP-SHA1
  * AES-GCM
  
Object content is encrypted using AES-GCM with generated DEKs which are stored in the S3 object metadata or in a separate instruction file (as configured).

# Code examples and API Documentation
 
For more information, including code samples and API documentation, please visit: https://aws.github.io/amazon-s3-encryption-client-dotnet/index.html
 
# Getting Help

We use the [GitHub issues](https://github.com/aws/amazon-s3-encryption-client-dotnet/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

If you think you may have found a bug, please open an [issue](https://github.com/aws/amazon-s3-encryption-client-dotnet/issues/new)

# Contributing

We welcome community contributions and pull requests. See
[CONTRIBUTING](./CONTRIBUTING.md) for information on how to set up a development
environment and submit code.

# Additional Resources

[AWS .NET GitHub Home Page](https://github.com/aws/dotnet)  
GitHub home for .NET development on AWS. You'll find libraries, tools, and resources to help you build .NET applications and services on AWS.

[AWS Developer Center - Explore .NET on AWS](https://aws.amazon.com/developer/language/net/)  
Find .NET code samples, step-by-step guides, videos, blog content, tools, and information about live events all in one place. 

[AWS Developer Blog - .NET](https://aws.amazon.com/blogs/developer/category/programing-language/dot-net/)  
Come and see what .NET developers at AWS are up to! Learn about new .NET software announcements, guides, and how-to's.

[@dotnetonaws](https://twitter.com/dotnetonaws) 
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.
