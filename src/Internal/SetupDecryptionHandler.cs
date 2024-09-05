using System;
using System.Collections.Generic;
using System.Linq;
using Amazon.Runtime;
using Amazon.S3.Model;
using Amazon.Runtime.Internal;
using Amazon.S3;
using GetObjectResponse = Amazon.S3.Model.GetObjectResponse;

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
            {
#if NETFRAMEWORK
                decryptedEnvelopeKeyKMS = DecryptedEnvelopeKeyKms(encryptedKMSEnvelopeKey, encryptionContext);
#else
                decryptedEnvelopeKeyKMS = DecryptedEnvelopeKeyKmsAsync(encryptedKMSEnvelopeKey, encryptionContext).GetAwaiter().GetResult();
#endif
            }

            var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
            if (getObjectResponse != null)
            {
#if NETFRAMEWORK
                DecryptObject(decryptedEnvelopeKeyKMS, getObjectResponse);
#else
                DecryptObjectAsync(decryptedEnvelopeKeyKMS, getObjectResponse).GetAwaiter().GetResult();
#endif
            }

            var completeMultiPartUploadRequest =  executionContext.RequestContext.Request.OriginalRequest as CompleteMultipartUploadRequest;
            var completeMultipartUploadResponse = executionContext.ResponseContext.Response as CompleteMultipartUploadResponse;
            if (completeMultipartUploadResponse != null)
            {
#if NETFRAMEWORK
                CompleteMultipartUpload(completeMultiPartUploadRequest);
#else
                CompleteMultipartUploadAsync(completeMultiPartUploadRequest).GetAwaiter().GetResult();
#endif
            }

            PostInvokeSynchronous(executionContext, decryptedEnvelopeKeyKMS);
        }

#if NETFRAMEWORK
        /// <summary>
        /// Decrypts envelope key using KMS client
        /// </summary>
        /// <param name="encryptedKMSEnvelopeKey">Encrypted key byte array to be decrypted</param>
        /// <param name="encryptionContext">Encryption context for KMS</param>
        /// <returns></returns>
        protected abstract byte[] DecryptedEnvelopeKeyKms(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext);
#endif

        /// <summary>
        /// Decrypts envelope key using KMS client asynchronously
        /// </summary>
        /// <param name="encryptedKMSEnvelopeKey">Encrypted key byte array to be decrypted</param>
        /// <param name="encryptionContext">Encryption context for KMS</param>
        /// <returns></returns>
        protected abstract System.Threading.Tasks.Task<byte[]> DecryptedEnvelopeKeyKmsAsync(byte[] encryptedKMSEnvelopeKey, Dictionary<string, string> encryptionContext);

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
            {
                decryptedEnvelopeKeyKMS = await DecryptedEnvelopeKeyKmsAsync(encryptedKMSEnvelopeKey, encryptionContext).ConfigureAwait(false);
            }

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
                    var instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse, EncryptionUtils.EncryptionInstructionFileV2Suffix);
                    instructionFileResponse = await GetInstructionFileAsync(instructionFileRequest).ConfigureAwait(false);
                }
                catch (AmazonS3Exception amazonS3Exception) when (amazonS3Exception.ErrorCode == EncryptionUtils.NoSuchKey)
                {
                    Logger.InfoFormat($"New instruction file with suffix {EncryptionUtils.EncryptionInstructionFileV2Suffix} doesn't exist. " +
                                      $"Try to get old instruction file with suffix {EncryptionUtils.EncryptionInstructionFileSuffix}. {amazonS3Exception.Message}");
                    try
                    {
                        var instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse, EncryptionUtils.EncryptionInstructionFileSuffix);
                        instructionFileResponse = await GetInstructionFileAsync(instructionFileRequest).ConfigureAwait(false);
                    }
                    catch (AmazonServiceException ace)
                    {
                         throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                    }
                }
                catch (AmazonServiceException ace)
                {
                    throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                }

                DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
            }
        }

        private async System.Threading.Tasks.Task<GetObjectResponse> GetInstructionFileAsync(GetObjectRequest instructionFileRequest)
        {
            var instructionFileResponse = await EncryptionClient.S3ClientForInstructionFile.GetObjectAsync(instructionFileRequest)
                    .ConfigureAwait(false);
            return instructionFileResponse;
        }

        /// <summary>
        /// Verify whether envelope is KMS or not
        /// Populate envelope key and encryption context
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <param name="encryptedKMSEnvelopeKey">Encrypted KMS envelope key</param>
        /// <param name="encryptionContext">KMS encryption context used for encryption and decryption</param>
        /// <returns></returns>
        protected bool KMSEnvelopeKeyIsPresent(IExecutionContext executionContext,
            out byte[] encryptedKMSEnvelopeKey, out Dictionary<string, string> encryptionContext)
        {
            var response = executionContext.ResponseContext.Response;
            var getObjectResponse = response as GetObjectResponse;
            encryptedKMSEnvelopeKey = null;
            encryptionContext = null;

            if (getObjectResponse != null)
            {
                var metadata = getObjectResponse.Metadata;
                EncryptionUtils.EnsureSupportedAlgorithms(metadata);

                var base64EncodedEncryptedKmsEnvelopeKey = metadata[EncryptionUtils.XAmzKeyV2];
                if (base64EncodedEncryptedKmsEnvelopeKey != null)
                {
                    var wrapAlgorithm = metadata[EncryptionUtils.XAmzWrapAlg];
                    if (!(EncryptionUtils.XAmzWrapAlgKmsContextValue.Equals(wrapAlgorithm) || EncryptionUtils.XAmzWrapAlgKmsValue.Equals(wrapAlgorithm)))
                    {
                        return false;
                    }

                    encryptedKMSEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedKmsEnvelopeKey);
                    encryptionContext = EncryptionUtils.GetMaterialDescriptionFromMetaData(metadata);

                    return true;
                }
            }
            return false;
        }

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
                EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(abortMultipartUploadRequest.UploadId, out _);
            }
        }

#if NETFRAMEWORK
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
                    var instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse, EncryptionUtils.EncryptionInstructionFileV2Suffix);
                    instructionFileResponse = GetInstructionFile(instructionFileRequest);
                }
                catch (AmazonS3Exception amazonS3Exception) when (amazonS3Exception.ErrorCode == EncryptionUtils.NoSuchKey)
                {
                    Logger.InfoFormat($"New instruction file with suffix {EncryptionUtils.EncryptionInstructionFileV2Suffix} doesn't exist. " +
                                      $"Try to get old instruction file with suffix {EncryptionUtils.EncryptionInstructionFileSuffix}. {amazonS3Exception.Message}");
                    try
                    {
                        var instructionFileRequest = EncryptionUtils.GetInstructionFileRequest(getObjectResponse, EncryptionUtils.EncryptionInstructionFileSuffix);
                        instructionFileResponse = GetInstructionFile(instructionFileRequest);
                    }
                    catch (AmazonServiceException ace)
                    {
                        throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                    }
                }
                catch (AmazonServiceException ace)
                {
                    throw new AmazonServiceException($"Unable to decrypt data for object {getObjectResponse.Key} in bucket {getObjectResponse.BucketName}", ace);
                }

                DecryptObjectUsingInstructionFile(getObjectResponse, instructionFileResponse);
            }
        }

        private GetObjectResponse GetInstructionFile(GetObjectRequest instructionFileRequest)
        {
            var instructionFileResponse = EncryptionClient.S3ClientForInstructionFile.GetObject(instructionFileRequest);
            return instructionFileResponse;
        }
#endif

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="getObjectResponse">The getObject response of InstructionFile.</param>
        /// <param name="instructionFileResponse">The getObject response whose contents are to be decrypted.</param>
        protected void DecryptObjectUsingInstructionFile(GetObjectResponse getObjectResponse, GetObjectResponse instructionFileResponse)
        {
            // Create an instruction object from the instruction file response
            var instructions = EncryptionUtils.BuildInstructionsUsingInstructionFileV2(instructionFileResponse, EncryptionClient.EncryptionMaterials);

            if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.CekAlgorithm))
            {
                // Decrypt the object with V2 instructions
                EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
            }
            else
            {
                ThrowIfLegacyReadIsDisabled();
                // Decrypt the object with V1 instructions
                EncryptionUtils.DecryptObjectUsingInstructions(getObjectResponse, instructions);
            }
        }

        /// <summary>
        /// Updates object where the object input stream contains the decrypted contents.
        /// </summary>
        /// <param name="getObjectResponse">The getObject response whose contents are to be decrypted.</param>
        /// <param name="decryptedEnvelopeKeyKMS">The decrypted envelope key to be use if KMS key wrapping is being used.  Or null if non-KMS key wrapping is being used.</param>
        protected void DecryptObjectUsingMetadata(GetObjectResponse getObjectResponse, byte[] decryptedEnvelopeKeyKMS)
        {
            // Create an instruction object from the object metadata
            EncryptionInstructions instructions = EncryptionUtils.BuildInstructionsFromObjectMetadata(getObjectResponse, EncryptionClient.EncryptionMaterials, decryptedEnvelopeKeyKMS);

            if (decryptedEnvelopeKeyKMS != null)
            {
                // Check if encryption context is present for KMS+context (v2) objects
                if (getObjectResponse.Metadata[EncryptionUtils.XAmzCekAlg] != null
                    && instructions.MaterialsDescription.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg))
                {
                    // If encryption context is present, ensure that the GCM algorithm name is in the EC as expected in v2
                    if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(getObjectResponse.Metadata[EncryptionUtils.XAmzCekAlg])
                        && EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.MaterialsDescription[EncryptionUtils.XAmzEncryptionContextCekAlg]))
                    {
                        // Decrypt the object with V2 instruction
                        EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
                    }
                    else
                    {
                        throw new AmazonCryptoException($"The content encryption algorithm used at encryption time does not match the algorithm stored for decryption time." +
                                                        " The object may be altered or corrupted.");
                    }
                }
                // Handle legacy KMS (v1) mode with GCM content encryption 
                // See https://github.com/aws/amazon-s3-encryption-client-dotnet/issues/26 for context. It fixes AWS SES encryption/decryption bug
                else if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(instructions.CekAlgorithm)) 
                {
                    // KMS (v1) without Encryption Context requires legacy mode to be enabled even when GCM is used for content encryption
                    ThrowIfLegacyReadIsDisabled();
                    EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
                }
                else if (EncryptionUtils.XAmzAesCbcPaddingCekAlgValue.Equals(instructions.CekAlgorithm))
                {
                    ThrowIfLegacyReadIsDisabled();
                    // Decrypt the object with V1 instruction
                    EncryptionUtils.DecryptObjectUsingInstructions(getObjectResponse, instructions);
                }
                else
                {
                    throw new AmazonCryptoException($"The content encryption algorithm used at encryption time does not match the algorithm stored for decryption time." +
                                                    " The object may be altered or corrupted.");
                }
            }
            else if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(getObjectResponse.Metadata[EncryptionUtils.XAmzCekAlg]))
            {
                // Decrypt the object with V2 instruction
                EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
            }
            // It is safe to assume, this is either non KMS encryption with V1 client or AES CBC
            // We don't need to check cek algorithm to be AES CBC, because non KMS encryption with V1 client doesn't set it
            else
            {
                ThrowIfLegacyReadIsDisabled();
                EncryptionUtils.DecryptObjectUsingInstructions(getObjectResponse, instructions);
            }
        }

        /// <summary>
        /// Throws if legacy security profile is disabled
        /// </summary>
        protected abstract void ThrowIfLegacyReadIsDisabled();

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
            if (!EncryptionClient.AllMultiPartUploadRequestContexts.ContainsKey(initiateMultiPartUploadRequest))
            {
                throw new AmazonServiceException($"Failed to find encryption context required to start multipart uploads for request {initiateMultiPartUploadRequest}");
            }

            EncryptionClient.CurrentMultiPartUploadKeys.TryAdd(initiateMultiPartResponse.UploadId, EncryptionClient.AllMultiPartUploadRequestContexts[initiateMultiPartUploadRequest]);

            // It is safe to remove the request as it has been already added to the CurrentMultiPartUploadKeys
            EncryptionClient.AllMultiPartUploadRequestContexts.TryRemove(initiateMultiPartUploadRequest, out _);
        }
    }
}
