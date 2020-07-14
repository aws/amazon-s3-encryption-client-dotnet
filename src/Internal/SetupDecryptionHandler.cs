﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Amazon.Runtime;
using Amazon.S3.Model;
using System.IO;
using System.Runtime.CompilerServices;
using Amazon.S3.Util;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.Util;
using Amazon.Runtime.SharedInterfaces;
using Amazon.S3.Internal;
using ThirdParty.Json.LitJson;

namespace Amazon.S3.Encryption.Internal
{
    /// <summary>
    /// Custom the pipeline handler to decrypt objects.
    /// </summary>
    public abstract class SetupDecryptionHandler : PipelineHandler
    {
        /// <summary>
        /// Construct instance of SetupDecryptionHandler.
        /// </summary>
        /// <param name="encryptionClient"></param>
        public SetupDecryptionHandler(AmazonS3EncryptionClientBase encryptionClient)
        {
            this.EncryptionClient = encryptionClient;
        }

        /// <summary>
        /// Gets the EncryptionClient property which is the AmazonS3EncryptionClientBase that is decrypting the object.
        /// </summary>
        public AmazonS3EncryptionClientBase EncryptionClient
        {
            get;
            private set;
        }

        /// <summary>
        /// Calls the post invoke logic after calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context which contains both the
        /// requests and response context.</param>
        public override void InvokeSync(IExecutionContext executionContext)
        {
            base.InvokeSync(executionContext);
            PostInvoke(executionContext);
        }

        /// <summary>
        /// Decrypt the object being downloaded.
        /// </summary>
        /// <param name="executionContext"></param>
        protected void PostInvoke(IExecutionContext executionContext)
        {
            byte[] encryptedKMSEnvelopeKey;
            Dictionary<string, string> encryptionContext;
            byte[] decryptedEnvelopeKeyKMS = null;

            if (KMSEnvelopeKeyIsPresent(executionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                decryptedEnvelopeKeyKMS = EncryptionClient.KMSClient.Decrypt(encryptedKMSEnvelopeKey, encryptionContext);

            PostInvokeSynchronous(executionContext, decryptedEnvelopeKeyKMS);
        }

#if AWS_ASYNC_API

        /// <summary>
        /// Calls the and post invoke logic after calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <typeparam name="T">The response type for the current request.</typeparam>
        /// <param name="executionContext">The execution context, it contains the
        /// request and response context.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public override async System.Threading.Tasks.Task<T> InvokeAsync<T>(IExecutionContext executionContext)
        {
            var response = await base.InvokeAsync<T>(executionContext).ConfigureAwait(false);
            await PostInvokeAsync(executionContext).ConfigureAwait(false);
            return response;
        }

        /// <summary>
        /// Decrypt the object being downloaded.
        /// </summary>
        /// <param name="executionContext"></param>
        protected async System.Threading.Tasks.Task PostInvokeAsync(IExecutionContext executionContext)
        {
            byte[] encryptedKMSEnvelopeKey;
            Dictionary<string, string> encryptionContext;
            byte[] decryptedEnvelopeKeyKMS = null;

            if (KMSEnvelopeKeyIsPresent(executionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                decryptedEnvelopeKeyKMS = await EncryptionClient.KMSClient.DecryptAsync(
                    encryptedKMSEnvelopeKey, encryptionContext).ConfigureAwait(false);

            PostInvokeSynchronous(executionContext, decryptedEnvelopeKeyKMS);
        }

#elif AWS_APM_API

        /// <summary>
        /// Calls the PostInvoke methods after calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the
        /// request and response context.</param>
        protected override void InvokeAsyncCallback(IAsyncExecutionContext executionContext)
        {
            IExecutionContext syncExecutionContext = ExecutionContext.CreateFromAsyncContext(executionContext);

            // Process the response if an exception hasn't occured
            if (executionContext.ResponseContext.AsyncResult.Exception == null)
            {
                byte[] encryptedKMSEnvelopeKey;
                Dictionary<string, string> encryptionContext;
                if (KMSEnvelopeKeyIsPresent(syncExecutionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                    throw new NotSupportedException("The AWS SDK for .NET Framework 3.5 version of " +
                        EncryptionClient.GetType().Name + " does not support KMS key wrapping via the async programming model.  " +
                        "Please use the synchronous version instead.");

                PostInvokeSynchronous(syncExecutionContext, null);
            }
            base.InvokeAsyncCallback(executionContext);
        }
#endif

        /// <summary>
        /// Verify whether envelope is KMS or not
        /// Populate envelope key and encryption context
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the
        /// request and response context.</param>
        /// <param name="encryptedKMSEnvelopeKey">KMS envelope key</param>
        /// <param name="encryptionContext">KMS encryption context used for encryption and decryption</param>
        /// <returns></returns>
        protected abstract bool KMSEnvelopeKeyIsPresent(IExecutionContext executionContext, 
            out byte[] encryptedKMSEnvelopeKey, out Dictionary<string, string> encryptionContext);

        /// <summary>
        /// Decrypt the object being downloaded.
        /// </summary>
        /// <param name="executionContext"></param>
        /// <param name="decryptedEnvelopeKeyKMS"></param>
        protected abstract void PostInvokeSynchronous(IExecutionContext executionContext, byte[] decryptedEnvelopeKeyKMS);
    }
}
