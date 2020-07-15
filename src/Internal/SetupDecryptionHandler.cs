using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Amazon.Runtime;
using Amazon.S3.Model;
using System.IO;
using System.Runtime.CompilerServices;
using Amazon.Extensions.S3.Encryption.Model;
using Amazon.S3.Util;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.Runtime.Internal.Util;
using Amazon.Util;
using Amazon.Runtime.SharedInterfaces;
using Amazon.S3.Internal;
using ThirdParty.Json.LitJson;
using GetObjectResponse = Amazon.S3.Model.GetObjectResponse;
using InitiateMultipartUploadRequest = Amazon.Extensions.S3.Encryption.Model.InitiateMultipartUploadRequest;

namespace Amazon.Extensions.S3.Encryption.Internal
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

            var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
            if (getObjectResponse != null)
            {
#if BCL
                DecryptObject(decryptedEnvelopeKeyKMS, getObjectResponse);
#elif AWS_ASYNC_API
                DecryptObjectAsync(decryptedEnvelopeKeyKMS, getObjectResponse).GetAwaiter().GetResult();
#endif
            }

            var completeMultiPartUploadRequest =  executionContext.RequestContext.Request.OriginalRequest as CompleteMultipartUploadRequest;
            var completeMultipartUploadResponse = executionContext.ResponseContext.Response as CompleteMultipartUploadResponse;
            if (completeMultipartUploadResponse != null)
            {
#if BCL
                CompleteMultipartUpload(completeMultiPartUploadRequest);
#elif AWS_ASYNC_API
                CompleteMultipartUploadAsync(completeMultiPartUploadRequest).GetAwaiter().GetResult();
#endif
            }

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
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        protected async System.Threading.Tasks.Task PostInvokeAsync(IExecutionContext executionContext)
        {
            byte[] encryptedKMSEnvelopeKey;
            Dictionary<string, string> encryptionContext;
            byte[] decryptedEnvelopeKeyKMS = null;

            if (KMSEnvelopeKeyIsPresent(executionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                decryptedEnvelopeKeyKMS = await EncryptionClient.KMSClient.DecryptAsync(
                    encryptedKMSEnvelopeKey, encryptionContext).ConfigureAwait(false);


            var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
            if (getObjectResponse != null)
            {
                await DecryptObjectAsync(decryptedEnvelopeKeyKMS, getObjectResponse).ConfigureAwait(false);
            }

            var completeMultiPartUploadRequest =  executionContext.RequestContext.Request.OriginalRequest as CompleteMultipartUploadRequest;
            var completeMultipartUploadResponse = executionContext.ResponseContext.Response as CompleteMultipartUploadResponse;
            if (completeMultipartUploadResponse != null)
            {
                await CompleteMultipartUploadAsync(completeMultiPartUploadRequest).ConfigureAwait(false);
            }

            PostInvokeSynchronous(executionContext, decryptedEnvelopeKeyKMS);
        }

        /// <summary>
        /// Mark multipart upload operation as completed and free resources asynchronously
        /// </summary>
        /// <param name="completeMultiPartUploadRequest">CompleteMultipartUploadRequest request which needs to marked as completed</param>
        /// <returns></returns>
        protected abstract System.Threading.Tasks.Task CompleteMultipartUploadAsync(CompleteMultipartUploadRequest completeMultiPartUploadRequest);

        /// <summary>
        /// Decrypt GetObjectResponse asynchronously
        /// Find which mode of encryption is used which can be either metadata (including KMS) or instruction file mode and
        /// use these instructions to decrypt GetObjectResponse asynchronously
        /// </summary>
        /// <param name="decryptedEnvelopeKeyKMS">decrypted envelope key for KMS</param>
        /// <param name="getObjectResponse">GetObjectResponse which needs to be decrypted</param>
        /// <returns></returns>
        /// <exception cref="AmazonServiceException">Exception thrown if GetObjectResponse decryption fails</exception>
        protected async System.Threading.Tasks.Task DecryptObjectAsync(byte[] decryptedEnvelopeKeyKMS, GetObjectResponse getObjectResponse)
        {
            if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse))
            {
                DecryptObjectUsingMetadata(getObjectResponse, decryptedEnvelopeKeyKMS);
            }
            else
            {
                GetObjectResponse instructionFileResponse = null;
                try
                {
                    GetObjectRequest instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse);
                    instructionFileResponse = await EncryptionClient.S3ClientForInstructionFile.GetObjectAsync(instructionFileRequest)
                        .ConfigureAwait(false);
                }
                catch (AmazonServiceException ace)
                {
                    throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                }

                if (EncryptionUtils.IsEncryptionInfoInInstructionFile(instructionFileResponse))
                {
                    DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
                }
            }
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

                var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
                if (getObjectResponse != null)
                {
                    DecryptObject(encryptedKMSEnvelopeKey, getObjectResponse);
                }

                var completeMultiPartUploadRequest =  executionContext.RequestContext.Request.OriginalRequest as CompleteMultipartUploadRequest;
                var completeMultipartUploadResponse = executionContext.ResponseContext.Response as CompleteMultipartUploadResponse;
                if (completeMultipartUploadResponse != null)
                {
                    CompleteMultipartUpload(completeMultiPartUploadRequest);
                }

                PostInvokeSynchronous(syncExecutionContext, null);
            }
            base.InvokeAsyncCallback(executionContext);
        }
#endif

        /// <summary>
        /// Verify whether envelope is KMS or not
        /// Populate envelope key and encryption context
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <param name="encryptedKMSEnvelopeKey">Encrypted KMS envelope key</param>
        /// <param name="encryptionContext">KMS encryption context used for encryption and decryption</param>
        /// <returns></returns>
        protected abstract bool KMSEnvelopeKeyIsPresent(IExecutionContext executionContext, 
            out byte[] encryptedKMSEnvelopeKey, out Dictionary<string, string> encryptionContext);

        /// <summary>
        /// Decrypt the object being downloaded.
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <param name="decryptedEnvelopeKeyKMS">Decrypted KMS envelope key</param>
        protected void PostInvokeSynchronous(IExecutionContext executionContext, byte[] decryptedEnvelopeKeyKMS)
        {
            var request = executionContext.RequestContext.Request;
            var response = executionContext.ResponseContext.Response;

            var initiateMultiPartUploadRequest = request.OriginalRequest as InitiateMultipartUploadRequest;
            var initiateMultiPartResponse = response as InitiateMultipartUploadResponse;
            if (initiateMultiPartResponse != null)
            {
                AddMultipartUploadEncryptionContext(initiateMultiPartUploadRequest, initiateMultiPartResponse);
            }

            var uploadPartRequest = request.OriginalRequest as UploadPartRequest;
            var uploadPartResponse = response as UploadPartResponse;
            if (uploadPartResponse != null)
            {
                UpdateMultipartUploadEncryptionContext(uploadPartRequest);
            }

            var abortMultipartUploadRequest = request.OriginalRequest as AbortMultipartUploadRequest;
            var abortMultipartUploadResponse = response as AbortMultipartUploadResponse;
            if (abortMultipartUploadResponse != null)
            {
                //Clear Context data since encryption is aborted
                EncryptionClient.CurrentMultiPartUploadKeys.Remove(abortMultipartUploadRequest.UploadId);
            }
        }

#if BCL
        /// <summary>
        /// Mark multipart upload operation as completed and free resources
        /// </summary>
        /// <param name="completeMultiPartUploadRequest">CompleteMultipartUploadRequest request which needs to marked as completed</param>
        /// <returns></returns>
        protected abstract void CompleteMultipartUpload(CompleteMultipartUploadRequest completeMultiPartUploadRequest);

        /// <summary>
        /// Find mode of encryption and decrypt GetObjectResponse
        /// </summary>
        /// <param name="decryptedEnvelopeKeyKMS">decrypted envelope key for KMS</param>
        /// <param name="getObjectResponse">GetObjectResponse which needs to be decrypted</param>
        /// <returns></returns>
        /// <exception cref="AmazonServiceException">Exception thrown if GetObjectResponse decryption fails</exception>
        protected void DecryptObject(byte[] decryptedEnvelopeKeyKMS, GetObjectResponse getObjectResponse)
        {
            if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse))
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
                    throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                }

                if (EncryptionUtils.IsEncryptionInfoInInstructionFile(instructionFileResponse))
                {
                    DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
                }
            }
        }
#endif

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="getObjectResponse">The getObject response of InstructionFile.</param>
        /// <param name="instructionFileResponse">The getObject response whose contents are to be decrypted.</param>
        protected abstract void DecryptObjectUsingInstructionFile(GetObjectResponse getObjectResponse, GetObjectResponse instructionFileResponse);

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="getObjectResponse">The getObject response whose contents are to be decrypted.</param>
        /// <param name="decryptedEnvelopeKeyKMS">The decrypted envelope key to be use if KMS key wrapping is being used.  Or null if non-KMS key wrapping is being used.</param>
        protected abstract void DecryptObjectUsingMetadata(GetObjectResponse getObjectResponse, byte[] decryptedEnvelopeKeyKMS);

        /// <summary>
        /// Update multipart upload encryption context for the given UploadPartRequest
        /// </summary>
        /// <param name="uploadPartRequest">UploadPartRequest whose context needs to be updated</param>
        protected abstract void UpdateMultipartUploadEncryptionContext(UploadPartRequest uploadPartRequest);

        /// <summary>
        /// Add multipart UploadId and encryption context to the current known multipart operations
        /// Encryption context is used decided the encryption instructions for next UploadPartRequest
        /// </summary>
        /// <param name="initiateMultiPartUploadRequest">InitiateMultipartUploadRequest whose encryption context needs to be saved</param>
        /// <param name="initiateMultiPartResponse">InitiateMultipartUploadResponse whose UploadId needs to be saved</param>
        protected void AddMultipartUploadEncryptionContext(InitiateMultipartUploadRequest initiateMultiPartUploadRequest, InitiateMultipartUploadResponse initiateMultiPartResponse)
        {
            var encryptedEnvelopeKey = initiateMultiPartUploadRequest.EncryptedEnvelopeKey;
            var envelopeKey = initiateMultiPartUploadRequest.EnvelopeKey;
            var iv = initiateMultiPartUploadRequest.IV;

            var contextForEncryption = new UploadPartEncryptionContext
            {
                StorageMode = (CryptoStorageMode)initiateMultiPartUploadRequest.StorageMode,
                EncryptedEnvelopeKey = encryptedEnvelopeKey,
                EnvelopeKey = envelopeKey,
                NextIV = iv,
                FirstIV = iv,
                PartNumber = 0
            };

            //Add context for encryption of next part
            this.EncryptionClient.CurrentMultiPartUploadKeys.Add(initiateMultiPartResponse.UploadId, contextForEncryption);
        }
    }
}
