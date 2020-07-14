using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Amazon.Runtime;
using Amazon.S3.Model;
using System.IO;

using Amazon.S3.Util;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.S3.Internal;
using Amazon.Util;

namespace Amazon.S3.Encryption.Internal
{
    /// <summary>
    /// Custom pipeline handler to encrypt the data as it is being uploaded to S3.
    /// </summary>
    public abstract class SetupEncryptionHandler : PipelineHandler
    {
        /// <summary>
        /// Construct an instance SetupEncryptionHandler.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupEncryptionHandler(AmazonS3EncryptionClientBase encryptionClient)
        {
            this.EncryptionClient = encryptionClient;
        }

        /// <summary>
        /// Gets the EncryptionClient property which is the AmazonS3EncryptionClient that is encrypting the object.
        /// </summary>
        public AmazonS3EncryptionClientBase EncryptionClient
        {
            get;
            private set;
        }

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context which contains both the
        /// requests and response context.</param>
        public override void InvokeSync(IExecutionContext executionContext)
        {
            PreInvoke(executionContext);
            base.InvokeSync(executionContext);
        }

        /// <summary>
        /// Encrypts the S3 object being uploaded.
        /// </summary>
        /// <param name="executionContext"></param>
        protected abstract void PreInvoke(IExecutionContext executionContext);

#if AWS_ASYNC_API

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <typeparam name="T">The response type for the current request.</typeparam>
        /// <param name="executionContext">The execution context, it contains the
        /// request and response context.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public override async System.Threading.Tasks.Task<T> InvokeAsync<T>(IExecutionContext executionContext)
        {
            await PreInvokeAsync(executionContext).ConfigureAwait(false);
            return await base.InvokeAsync<T>(executionContext).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypts the S3 object being uploaded.
        /// </summary>
        /// <param name="executionContext"></param>
        protected abstract System.Threading.Tasks.Task PreInvokeAsync(IExecutionContext executionContext);

#elif AWS_APM_API

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context which contains both the
        /// requests and response context.</param>
        /// <returns>IAsyncResult which represent an async operation.</returns>
        public override IAsyncResult InvokeAsync(IAsyncExecutionContext executionContext)
        {
            IExecutionContext syncExecutionContext = ExecutionContext.CreateFromAsyncContext(executionContext);

            if (NeedToGenerateKMSInstructions(syncExecutionContext))
                throw new NotSupportedException("The AWS SDK for .NET Framework 3.5 version of " +
                    EncryptionClient.GetType().Name + " does not support KMS key wrapping via the async programming model.  " +
                    "Please use the synchronous version instead.");

            PreInvokeSynchronous(syncExecutionContext, null);
            return base.InvokeAsync(executionContext);
        }

#endif

        protected bool NeedToGenerateKMSInstructions(IExecutionContext executionContext)
        {
            return EncryptionClient.EncryptionMaterials.KMSKeyID != null &&
                NeedToGenerateInstructions(executionContext);
        }

        internal static bool NeedToGenerateInstructions(IExecutionContext executionContext)
        {
            var request = executionContext.RequestContext.OriginalRequest;
            var putObjectRequest = request as PutObjectRequest;
            var initiateMultiPartUploadRequest = request as InitiateMultipartUploadRequest;
            return putObjectRequest != null || initiateMultiPartUploadRequest != null;
        }

        internal abstract void PreInvokeSynchronous(IExecutionContext executionContext, EncryptionInstructions instructions);

        /// <summary>
        /// Make sure that the storage mode and encryption materials are compatible.
        /// The client only supports KMS key wrapping in metadata storage mode.
        /// </summary>
        internal void ValidateConfigAndMaterials()
        {
            var usingKMSKeyWrapping = this.EncryptionClient.EncryptionMaterials.KMSKeyID != null;
            var usingMetadataStorageMode = EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata;
            if (usingKMSKeyWrapping && !usingMetadataStorageMode)
                throw new AmazonClientException("AmazonS3EncryptionClient only supports KMS key wrapping in metadata storage mode. " +
                    "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.");
        }
    }
}
