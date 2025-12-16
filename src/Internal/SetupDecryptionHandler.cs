using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Amazon.Runtime;
using Amazon.S3.Model;
using Amazon.Runtime.Internal;
using Amazon.S3;
using GetObjectResponse = Amazon.S3.Model.GetObjectResponse;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Extensions.S3.Encryption.Util.ContentMetaDataUtils;

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
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC MAY support re-encryption/key rotation via Instruction Files.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC MUST NOT support providing a custom Instruction File suffix on ordinary writes; custom suffixes MUST only be used during re-encryption.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC SHOULD support providing a custom Instruction File suffix on GetObject requests, regardless of whether or not re-encryption is supported.
            
            using (TelemetryUtilities.CreateSpan(EncryptionClient, Constants.SetupDecryptionHandlerSpanName, null, Amazon.Runtime.Telemetry.Tracing.SpanKind.CLIENT))
            {
                var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
                
                byte[] encryptedKMSEnvelopeKey;
                Dictionary<string, string> encryptionContext;
                byte[] decryptedEnvelopeKeyKMS = null;
                
                //= ../specification/s3-encryption/client.md#required-api-operations
                //# - GetObject MUST be implemented by the S3EC.
                if (getObjectResponse != null && ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(getObjectResponse.Metadata))
                {
                    var wrapAlgorithm = EncryptionUtils.GetEncryptedDataKeyAlgorithm(getObjectResponse.Metadata);
                    var isNonKmsWrappingAlg = !EncryptionUtils.IsKmsWrappingAlgV3(wrapAlgorithm);
                    ContentMetaDataV3Utils.ValidateV3ObjectMetadata(getObjectResponse.Metadata, 
                        isNonKmsWrappingAlg);
                }
                
                if (getObjectResponse != null && KMSEnvelopeKeyIsPresent(executionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                {
#if NETFRAMEWORK
                    decryptedEnvelopeKeyKMS = DecryptedEnvelopeKeyKms(encryptedKMSEnvelopeKey, encryptionContext);
#else
                    decryptedEnvelopeKeyKMS = DecryptedEnvelopeKeyKmsAsync(encryptedKMSEnvelopeKey, encryptionContext).GetAwaiter().GetResult();
#endif
                }
                
                if (getObjectResponse != null)
                {
                    //= ../specification/s3-encryption/client.md#required-api-operations
                    //# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
#if NETFRAMEWORK
                    DecryptObject(decryptedEnvelopeKeyKMS, getObjectResponse);
#else
                    DecryptObjectAsync(decryptedEnvelopeKeyKMS, getObjectResponse).GetAwaiter().GetResult();
#endif
                }
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //# - CompleteMultipartUpload MAY be implemented by the S3EC.
                
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
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC MAY support re-encryption/key rotation via Instruction Files.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC MUST NOT support providing a custom Instruction File suffix on ordinary writes; custom suffixes MUST only be used during re-encryption.
            
            //= ../specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //= type=exception
            //# The S3EC SHOULD support providing a custom Instruction File suffix on GetObject requests, regardless of whether or not re-encryption is supported.
            
            using (TelemetryUtilities.CreateSpan(EncryptionClient, Constants.SetupDecryptionHandlerSpanName, null, Amazon.Runtime.Telemetry.Tracing.SpanKind.CLIENT))
            {
                var getObjectResponse = executionContext.ResponseContext.Response as GetObjectResponse;
                byte[] encryptedKMSEnvelopeKey;
                Dictionary<string, string> encryptionContext;
                byte[] decryptedEnvelopeKeyKMS = null;
                
                //= ../specification/s3-encryption/client.md#required-api-operations
                //# - GetObject MUST be implemented by the S3EC.
                if (getObjectResponse != null && ContentMetaDataV3Utils.IsV3ObjectInMetaDataMode(getObjectResponse.Metadata))
                {
                    var wrapAlgorithm = EncryptionUtils.GetEncryptedDataKeyAlgorithm(getObjectResponse.Metadata);
                    var isNonKmsWrappingAlg = !EncryptionUtils.IsKmsWrappingAlgV3(wrapAlgorithm);
                    ContentMetaDataV3Utils.ValidateV3ObjectMetadata(getObjectResponse.Metadata, 
                        isNonKmsWrappingAlg);
                }

                if (getObjectResponse != null && KMSEnvelopeKeyIsPresent(executionContext, out encryptedKMSEnvelopeKey, out encryptionContext))
                {
                    decryptedEnvelopeKeyKMS = await DecryptedEnvelopeKeyKmsAsync(encryptedKMSEnvelopeKey, encryptionContext).ConfigureAwait(false);
                }
                
                if (getObjectResponse != null)
                {
                    //= ../specification/s3-encryption/client.md#required-api-operations
                    //# - GetObject MUST decrypt data received from the S3 server and return it as plaintext.
                    await DecryptObjectAsync(decryptedEnvelopeKeyKMS, getObjectResponse).ConfigureAwait(false);
                }
                
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //# - CompleteMultipartUpload MAY be implemented by the S3EC.

                var completeMultiPartUploadRequest =  executionContext.RequestContext.Request.OriginalRequest as CompleteMultipartUploadRequest;
                var completeMultipartUploadResponse = executionContext.ResponseContext.Response as CompleteMultipartUploadResponse;
                if (completeMultipartUploadResponse != null)
                {
                    await CompleteMultipartUploadAsync(completeMultiPartUploadRequest).ConfigureAwait(false);
                }

                PostInvokeSynchronous(executionContext, decryptedEnvelopeKeyKMS);
            }
        }
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //= type=implication
        //# - CompleteMultipartUpload MUST complete the multipart upload.
        
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
            /*
            * Per inputs from Crypto Tools team, the behavior to return plaintext violates the security guarantees of the library.
            * A threat actor with write access to S3 can replace an encrypted object with a plaintext object, and the GetObject operation succeeds. 
            * This violates the integrity guarantee, i.e. that the original plaintext has not replaced with a different plaintext. 
            * Therefore, plaintext objects must be handled outside of the security boundary of the S3EC.
            */
            if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse))
            {
                DecryptObjectUsingMetadata(getObjectResponse, decryptedEnvelopeKeyKMS);
            }
            else
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=implication
                //# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
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
                    catch (AmazonS3Exception amazonS3ExceptionInner) when (amazonS3ExceptionInner.ErrorCode == EncryptionUtils.NoSuchKey)
                    {
                        throw new AmazonServiceException($"Exception encountered while fetching Instruction File. Ensure the object you are" +
                            $" attempting to decrypt has been encrypted using the S3 Encryption Client.", amazonS3ExceptionInner);
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
        /// Since, S3EC .NET does not support instruction file for KMS wrapping keys
        /// this method only works with metadata of the object.
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

                var base64EncodedEncryptedKmsEnvelopeKey = EncryptionUtils.GetEncryptedDataKeyV2OrV3InMetaDataMode(metadata);
                if (base64EncodedEncryptedKmsEnvelopeKey != null)
                {
                    var wrapAlgorithm = EncryptionUtils.GetEncryptedDataKeyAlgorithm(metadata);
                    if (!(EncryptionUtils.XAmzWrapAlgKmsContextValue.Equals(wrapAlgorithm) || EncryptionUtils.XAmzWrapAlgKmsValue.Equals(wrapAlgorithm)))
                    {
                        return false;
                    }

                    encryptedKMSEnvelopeKey = Convert.FromBase64String(base64EncodedEncryptedKmsEnvelopeKey);
                    encryptionContext = EncryptionUtils.GetEncryptionContextFromMetaData(metadata);

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
            // PostInvokeSynchronous is called by both PostInvoke and PostInvokeAsync
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
            
            //= ../specification/s3-encryption/client.md#optional-api-operations
            //= type=implication
            //# - AbortMultipartUpload MAY be implemented by the S3EC.
            var abortMultipartUploadRequest = request.OriginalRequest as AbortMultipartUploadRequest;
            var abortMultipartUploadResponse = response as AbortMultipartUploadResponse;
            if (abortMultipartUploadResponse != null)
            {
                //= ../specification/s3-encryption/client.md#optional-api-operations
                //= type=implication
                //# - AbortMultipartUpload MUST abort the multipart upload.
                //Clear Context data since encryption is aborted
                EncryptionClient.CurrentMultiPartUploadKeys.TryRemove(abortMultipartUploadRequest.UploadId, out _);
            }
        }
        
#if NETFRAMEWORK
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //= type=implication
        //# - CompleteMultipartUpload MUST complete the multipart upload.
        
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
            /*
            * Per inputs from Crypto Tools team, the behavior to return plaintext violates the security guarantees of the library.
            * A threat actor with write access to S3 can replace an encrypted object with a plaintext object, and the GetObject operation succeeds. 
            * This violates the integrity guarantee, i.e. that the original plaintext has not replaced with a different plaintext. 
            * Therefore, plaintext objects must be handled outside of the security boundary of the S3EC.
            */
            if (EncryptionUtils.IsEncryptionInfoInMetadata(getObjectResponse))
            {
                DecryptObjectUsingMetadata(getObjectResponse, decryptedEnvelopeKeyKMS);
            }
            else
            {
                //= ../specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=implication
                //# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
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
                    catch (AmazonS3Exception amazonS3ExceptionInner) when (amazonS3ExceptionInner.ErrorCode == EncryptionUtils.NoSuchKey)
                    {
                        throw new AmazonServiceException($"Exception encountered while fetching Instruction File. Ensure the object you are" +
                            $" attempting to decrypt has been encrypted using the S3 Encryption Client.", amazonS3ExceptionInner);
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
            // The code path implicitly considers when on instruction file mode its non KMS wrapping key which is also true.
            Dictionary<string, string> pairsFromInsFile;
            using (var textReader = new StreamReader(instructionFileResponse.ResponseStream))
            {
                pairsFromInsFile = JsonUtils.ToDictionary(textReader.ReadToEnd());
            }

            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // V3 Objects are objects with key commitment
            if (ContentMetaDataV3Utils.IsV3Object(getObjectResponse.Metadata))
            {
                ContentMetaDataV3Utils.ValidateV3InstructionFile(getObjectResponse.Metadata, pairsFromInsFile);
                EncryptionUtils.EnsureSupportedAlgorithms(getObjectResponse.Metadata, pairsFromInsFile);
                var instructionsV3 = EncryptionUtils.BuildInstructionsForNonKmsV3InInstructionMode(getObjectResponse.Metadata, pairsFromInsFile, EncryptionClient.EncryptionMaterials);
                EncryptionUtils.DecryptObjectUsingV3Instructions(getObjectResponse, instructionsV3);
                return;
            }
            // Create an instruction object from the instruction file response
            var instructions = EncryptionUtils.BuildInstructionsUsingInstructionFileV2(pairsFromInsFile, EncryptionClient.EncryptionMaterials);

            if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite)))
            {
                // Decrypt the object with V2 instructions
                EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
            }
            else
            {
                //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
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
            
            //= ../specification/s3-encryption/key-commitment.md#commitment-policy
            //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
            // V3 Objects are objects with key commitment
            if (ContentMetaDataV3Utils.IsV3Object(getObjectResponse.Metadata))
            {
                EncryptionUtils.DecryptObjectUsingV3Instructions(getObjectResponse, instructions);
                return;
            }
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
                else if (EncryptionUtils.XAmzAesGcmCekAlgValue.Equals(AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite))) 
                {
                    //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                    //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
                    // KMS (v1) without Encryption Context requires legacy mode to be enabled even when GCM is used for content encryption
                    ThrowIfLegacyReadIsDisabled();
                    //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                    //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
                    EncryptionUtils.DecryptObjectUsingInstructionsGcm(getObjectResponse, instructions);
                }
                else if (EncryptionUtils.XAmzAesCbcPaddingCekAlgValue.Equals(AlgorithmSuite.GetRepresentativeValue(instructions.AlgorithmSuite)))
                {
                    //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                    //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
                    ThrowIfLegacyReadIsDisabled();
                    //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                    //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
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
                //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
                ThrowIfLegacyReadIsDisabled();
                //= ../specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
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
