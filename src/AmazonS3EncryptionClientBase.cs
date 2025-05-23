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
