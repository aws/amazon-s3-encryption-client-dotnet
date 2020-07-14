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
        protected void PostInvokeSynchronous(IExecutionContext executionContext, byte[] decryptedEnvelopeKeyKMS)
        {
            var request = executionContext.RequestContext.Request;
            var response = executionContext.ResponseContext.Response;

            var initiateMultiPartUploadRequest = request.OriginalRequest as InitiateMultipartUploadRequest;
            var initiateMultiPartResponse = response as InitiateMultipartUploadResponse;
            if (initiateMultiPartResponse != null)
            {
                byte[] encryptedEnvelopeKey = initiateMultiPartUploadRequest.EncryptedEnvelopeKey;
                byte[] envelopeKey = initiateMultiPartUploadRequest.EnvelopeKey;
                byte[] iv = initiateMultiPartUploadRequest.IV;

                UploadPartEncryptionContext contextForEncryption = new UploadPartEncryptionContext();
                contextForEncryption.StorageMode = initiateMultiPartUploadRequest.StorageMode;
                contextForEncryption.EncryptedEnvelopeKey = encryptedEnvelopeKey;
                contextForEncryption.EnvelopeKey = envelopeKey;
                contextForEncryption.NextIV = iv;
                contextForEncryption.FirstIV = iv;
                contextForEncryption.PartNumber = 0;

                //Add context for encryption of next part
                this.EncryptionClient.CurrentMultiPartUploadKeys.Add(initiateMultiPartResponse.UploadId, contextForEncryption);
            }

            var uploadPartRequest = request.OriginalRequest as UploadPartRequest;
            var uploadPartResponse = response as UploadPartResponse;
            if (uploadPartResponse != null)
            {
                string uploadID = uploadPartRequest.UploadId;
                UploadPartEncryptionContext encryptedUploadedContext = null;

                if (!this.EncryptionClient.CurrentMultiPartUploadKeys.TryGetValue(uploadID, out encryptedUploadedContext))
                    throw new AmazonS3Exception("encryption context for multi part upload not found");

                if (uploadPartRequest.IsLastPart == false)
                {
                    object stream = null;

                    if (!((Amazon.Runtime.Internal.IAmazonWebServiceRequest)uploadPartRequest).RequestState.TryGetValue(AmazonS3EncryptionClient.S3CryptoStream, out stream))
                        throw new AmazonS3Exception("cannot retrieve S3 crypto stream from request state, hence cannot get Initialization vector for next uploadPart ");

                    var encryptionStream = stream as AESEncryptionUploadPartStream;
                    encryptedUploadedContext.NextIV = encryptionStream.InitializationVector;
                }

            }

            var getObjectResponse = response as GetObjectResponse;
            if (getObjectResponse != null)
            {
                if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse) == true)
                {
                    DecryptObjectUsingMetadata(getObjectResponse, decryptedEnvelopeKeyKMS);
                }
                else
                {
                    GetObjectResponse instructionFileResponse = null;
                    try
                    {
                        GetObjectRequest instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse);
                        instructionFileResponse = this.EncryptionClient.S3ClientForInstructionFile.GetObject(instructionFileRequest);
                    }
                    catch (AmazonServiceException ace)
                    {
                        throw new AmazonServiceException(string.Format(CultureInfo.InvariantCulture, "Unable to decrypt data for object {0} in bucket {1}",
                            getObjectResponse.Key, getObjectResponse.BucketName), ace);
                    }

                    if (EncryptionUtils.IsEncryptionInfoInInstructionFile(instructionFileResponse) == true)
                    {
                        DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
                    }
                }
            }

            var completeMultiPartUploadRequest = request.OriginalRequest as CompleteMultipartUploadRequest;
            var completeMultipartUploadResponse = response as CompleteMultipartUploadResponse;
            if (completeMultipartUploadResponse != null)
            {
                UploadPartEncryptionContext context = this.EncryptionClient.CurrentMultiPartUploadKeys[completeMultiPartUploadRequest.UploadId];

                if (context.StorageMode == CryptoStorageMode.InstructionFile)
                {
                    byte[] envelopeKey = context.EnvelopeKey;
                    byte[] iv = context.FirstIV;
                    byte[] encryptedEnvelopeKey = context.EncryptedEnvelopeKey;
                    EncryptionInstructions instructions = new EncryptionInstructions(EncryptionClient.EncryptionMaterials.MaterialsDescription, envelopeKey, encryptedEnvelopeKey, iv);

                    PutObjectRequest instructionFileRequest = EncryptionUtils.CreateInstructionFileRequest(completeMultiPartUploadRequest, instructions);

                    this.EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
                }

                //Clear Context data since encryption is completed
                this.EncryptionClient.CurrentMultiPartUploadKeys.Clear();
            }
        }

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="instructionFileResponse">
        /// The getObject response of InstructionFile.
        /// </param>
        /// <param name="response">
        /// The getObject response whose contents are to be decrypted.
        /// </param>
        protected abstract void DecryptObjectUsingInstructionFile(GetObjectResponse response, GetObjectResponse instructionFileResponse);

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="objectResponse">
        /// The getObject response whose contents are to be decrypted.
        /// </param>
        /// <param name="decryptedEnvelopeKeyKMS">
        /// The decrypted envelope key to be use if KMS key wrapping is being used.  Or null if non-KMS key wrapping is being used.
        /// </param>
        protected abstract void DecryptObjectUsingMetadata(GetObjectResponse objectResponse,byte[] decryptedEnvelopeKeyKMS);
    }
}
