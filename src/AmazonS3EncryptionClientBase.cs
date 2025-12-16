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

using Amazon.Runtime;
using Amazon.S3.Internal;
using Amazon.S3.Model;
using Amazon.KeyManagementService;
using Amazon.S3;

namespace Amazon.Extensions.S3.Encryption
{
    //= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=exception
    //# The S3EC MUST support the option to enable or disable legacy wrapping algorithms.
    
    //= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=exception
    //# The option to enable legacy wrapping algorithms MUST be set to false by default.
    
    //= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=exception
    //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
    
    //= ../specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
    //= type=exception
    //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
    
    //= ../specification/s3-encryption/client.md#enable-delayed-authentication
    //= type=exception
    //# The S3EC MUST support the option to enable or disable Delayed Authentication mode.
    
    //= ../specification/s3-encryption/client.md#enable-delayed-authentication
    //= type=exception
    //# Delayed Authentication mode MUST be set to false by default.
    
    //= ../specification/s3-encryption/client.md#enable-delayed-authentication
    //= type=exception
    //# When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
    
    //= ../specification/s3-encryption/client.md#enable-delayed-authentication
    //= type=exception
    //# When disabled the S3EC MUST NOT release plaintext from a stream which has not been authenticated.
    
    //= ../specification/s3-encryption/client.md#set-buffer-size
    //= type=exception
    //# The S3EC SHOULD accept a configurable buffer size which refers to the maximum ciphertext length in bytes to store in memory when Delayed Authentication mode is disabled.

    //= ../specification/s3-encryption/client.md#set-buffer-size
    //= type=exception
    //# If Delayed Authentication mode is enabled, and the buffer size has been set to a value other than its default, the S3EC MUST throw an exception.
    
    //= ../specification/s3-encryption/client.md#set-buffer-size
    //= type=exception
    //# If Delayed Authentication mode is disabled, and no buffer size is provided, the S3EC MUST set the buffer size to a reasonable default.

    //= ../specification/s3-encryption/client.md#wrapped-s3-client-s
    //= type=exception
    //# The S3EC MUST support the option to provide an SDK S3 client instance during its initialization.
    
    //= ../specification/s3-encryption/client.md#wrapped-s3-client-s
    //= type=exception
    //# The S3EC MUST NOT support use of S3EC as the provided S3 client during its initialization; it MUST throw an exception in this case.
    
    //= ../specification/s3-encryption/client.md#randomness
    //= type=exception
    //# The S3EC MAY accept a source of randomness during client initialization.
    
    //= ../specification/s3-encryption/client.md#aws-sdk-compatibility
    //= type=implication
    //# The S3EC MUST adhere to the same interface for API operations as the conventional AWS SDK S3 client.
    
    //= ../specification/s3-encryption/client.md#aws-sdk-compatibility
    //= type=implication
    //# The S3EC SHOULD support invoking operations unrelated to client-side encryption e.g.
    
    /// <summary>
    /// Base class for AmazonS3Encryption clients
    /// Encapsulates common properties and methods of the encryption clients
    /// </summary>
    public abstract class AmazonS3EncryptionClientBase : AmazonS3Client, IAmazonS3Encryption
    {
        private IAmazonKeyManagementService kmsClient;
        private readonly object kmsClientLock = new object();

        internal EncryptionMaterialsBase EncryptionMaterials
        {
            get;
            private set;
        }

        internal IAmazonKeyManagementService KMSClient
        {
            get
            {
                if (kmsClient == null)
                {
                    lock (kmsClientLock)
                    {
                        if (kmsClient == null)
                        {
                            if (this.S3CryptoConfig.KmsConfig != null)
                            {
                                kmsClient = new AmazonKeyManagementServiceClient(this.Config.DefaultAWSCredentials, 
                                    this.S3CryptoConfig.KmsConfig);
                            }
                            else
                            {
                                var kmsConfig = new AmazonKeyManagementServiceConfig
                                {
                                    RegionEndpoint = this.Config.RegionEndpoint,
                                    Timeout = this.Config.Timeout
                                };

                                var proxySettings = this.Config.GetWebProxy();
                                if(proxySettings != null)
                                {
                                    kmsConfig.SetWebProxy(proxySettings);
                                }
                                
                                kmsClient = new AmazonKeyManagementServiceClient(this.Config.DefaultAWSCredentials, kmsConfig);
                            }
                        }
                    }
                }
                return kmsClient;
            }
        }

        private AmazonS3Client s3ClientForInstructionFile;
        
        internal AmazonS3Client S3ClientForInstructionFile
	    {
	        get
	        {
	            if (s3ClientForInstructionFile == null)
	            {
                    s3ClientForInstructionFile = new AmazonS3Client(this.Config.DefaultAWSCredentials, S3CryptoConfig);
                }
	            return s3ClientForInstructionFile;
	        }
	    }

        internal AmazonS3CryptoConfigurationBase S3CryptoConfig { get; set; }
        internal readonly System.Collections.Concurrent.ConcurrentDictionary<string, UploadPartEncryptionContext> CurrentMultiPartUploadKeys =
            new System.Collections.Concurrent.ConcurrentDictionary<string, UploadPartEncryptionContext>();
        internal readonly System.Collections.Concurrent.ConcurrentDictionary<InitiateMultipartUploadRequest, UploadPartEncryptionContext> AllMultiPartUploadRequestContexts =
            new System.Collections.Concurrent.ConcurrentDictionary<InitiateMultipartUploadRequest, UploadPartEncryptionContext>();
        internal const string S3CryptoStream = "S3-Crypto-Stream";

        #region Constructors
        /// <summary>
        /// Constructs AmazonS3EncryptionClient with the Encryption materials and credentials loaded from the application's
        /// default configuration, and if unsuccessful from the Instance Profile service on an EC2 instance.
        /// 
        /// Example App.config with credentials set. 
        /// <code>
        /// &lt;?xml version="1.0" encoding="utf-8" ?&gt;
        /// &lt;configuration&gt;
        ///     &lt;appSettings&gt;
        ///         &lt;add key="AWSProfileName" value="AWS Default"/&gt;
        ///     &lt;/appSettings&gt;
        /// &lt;/configuration&gt;
        /// </code>
        /// 
        /// </summary>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(EncryptionMaterialsBase materials)
            : base()
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with the Encryption materials and credentials loaded from the application's
        /// default configuration, and if unsuccessful from the Instance Profile service on an EC2 instance.
        /// 
        /// Example App.config with credentials set. 
        /// <code>
        /// &lt;?xml version="1.0" encoding="utf-8" ?&gt;
        /// &lt;configuration&gt;
        ///     &lt;appSettings&gt;
        ///         &lt;add key="AWSProfileName" value="AWS Default"/&gt;
        ///     &lt;/appSettings&gt;
        /// &lt;/configuration&gt;
        /// </code>
        /// 
        /// </summary>
        /// <param name="region">
        /// The region to connect.
        /// </param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(RegionEndpoint region, EncryptionMaterialsBase materials)
            : base(region)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with the Encryption materials, 
        /// AmazonS3 CryptoConfiguration object and credentials loaded from the application's
        /// default configuration, and if unsuccessful from the Instance Profile service on an EC2 instance.
        /// 
        /// Example App.config with credentials set. 
        /// <code>
        /// &lt;?xml version="1.0" encoding="utf-8" ?&gt;
        /// &lt;configuration&gt;
        ///     &lt;appSettings&gt;
        ///         &lt;add key="AWSProfileName" value="AWS Default"/&gt;
        ///     &lt;/appSettings&gt;
        /// &lt;/configuration&gt;
        /// </code>
        /// 
        /// </summary>
        /// <param name="config">
        /// The AmazonS3EncryptionClient CryptoConfiguration Object
        /// </param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(AmazonS3CryptoConfigurationBase config, EncryptionMaterialsBase materials)
            : base(config)
        {
            this.EncryptionMaterials = materials;
            S3CryptoConfig = config;
        }
        
        //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
        //# The S3EC MAY support directly configuring the wrapped SDK clients through its initialization.
        
        //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
        //# For example, the S3EC MAY accept a credentials provider instance during its initialization.
        
        //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
        //# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped S3 clients.
        
        //= ../specification/s3-encryption/client.md#inherited-sdk-configuration
        //# If the S3EC accepts SDK client configuration, the configuration MUST be applied to all wrapped SDK clients including the KMS client.

        /// <summary>
        ///  Constructs AmazonS3EncryptionClient with AWS Credentials and Encryption materials.
        /// </summary>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        /// <param name="credentials">AWS Credentials</param>
        public AmazonS3EncryptionClientBase(AWSCredentials credentials, EncryptionMaterialsBase materials)
            : base(credentials)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Credentials, Region and Encryption materials
        /// </summary>
        /// <param name="credentials">AWS Credentials</param>
        /// <param name="region">The region to connect.</param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(AWSCredentials credentials, RegionEndpoint region, EncryptionMaterialsBase materials)
            : base(credentials, region)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Credentials, AmazonS3CryptoConfigurationBase Configuration object
        /// and Encryption materials
        /// </summary>
        /// <param name="credentials">AWS Credentials</param>
        /// <param name="config">The AmazonS3EncryptionClient CryptoConfiguration Object</param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(AWSCredentials credentials, AmazonS3CryptoConfigurationBase config, EncryptionMaterialsBase materials)
            : base(credentials, config)
        {
            this.EncryptionMaterials = materials;
            S3CryptoConfig = config;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID,
        /// AWS Secret Key and Encryption materials
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="materials">The encryption materials to be used to encrypt and decrypt envelope key.</param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID,
        /// AWS Secret Key, Region and Encryption materials
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="region">The region to connect.</param>
        /// <param name="materials">The encryption materials to be used to encrypt and decrypt envelope key.</param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, RegionEndpoint region, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey, region)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID, Secret Key,
        /// AmazonS3 CryptoConfiguration object and Encryption materials.
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="config">The AmazonS3EncryptionClient CryptoConfiguration Object</param>
        /// <param name="materials">The encryption materials to be used to encrypt and decrypt envelope key.</param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, AmazonS3CryptoConfigurationBase config, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey, config)
        {
            this.EncryptionMaterials = materials;
            S3CryptoConfig = config;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID, Secret Key,
        /// SessionToken and Encryption materials.
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="awsSessionToken">AWS Session Token</param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID, Secret Key,
        ///  SessionToken, Region and Encryption materials.
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="awsSessionToken">AWS Session Token</param>
        /// <param name="region">The region to connect.</param>
        /// <param name="materials">The encryption materials to be used to encrypt and decrypt envelope key.</param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, RegionEndpoint region, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, region)
        {
            this.EncryptionMaterials = materials;
        }

        /// <summary>
        /// Constructs AmazonS3EncryptionClient with AWS Access Key ID, Secret Key, SessionToken
        /// AmazonS3EncryptionClient CryptoConfiguration object and Encryption materials.
        /// </summary>
        /// <param name="awsAccessKeyId">AWS Access Key ID</param>
        /// <param name="awsSecretAccessKey">AWS Secret Access Key</param>
        /// <param name="awsSessionToken">AWS Session Token</param>
        /// <param name="config">The AmazonS3EncryptionClient CryptoConfiguration Object</param>
        /// <param name="materials">
        /// The encryption materials to be used to encrypt and decrypt envelope key.
        /// </param>
        public AmazonS3EncryptionClientBase(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, AmazonS3CryptoConfigurationBase config, EncryptionMaterialsBase materials)
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, config)
        {
            this.EncryptionMaterials = materials;
            S3CryptoConfig = config;
        }        

        #endregion


        /// <summary>
        /// Turn off response logging because it will interfere with decrypt of the data coming back from S3.
        /// </summary>
        protected override bool SupportResponseLogging
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Dispose this instance
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            lock (kmsClientLock)
            {
                if (kmsClient != null)
                {
                    kmsClient.Dispose();
                    kmsClient = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}
