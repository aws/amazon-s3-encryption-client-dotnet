using System;
using System.Collections.Generic;
using Amazon.Runtime;
using Amazon.S3.Model;
using Amazon.Runtime.Internal;
using Amazon.Extensions.S3.Encryption.Util;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    //= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
    //= type=exception
    //# Attempts to encrypt using AES-CTR MUST fail.
    
    //= ../specification/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
    //= type=exception
    //# Attempts to encrypt using key committing AES-CTR MUST fail.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObject MUST be implemented by the S3EC.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObject MUST delete the given object key.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObject MUST delete the associated instruction file using the default instruction file suffix.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObjects MUST be implemented by the S3EC.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObjects MUST delete each of the given objects.
    
    //= ../specification/s3-encryption/client.md#required-api-operations
    //= type=exception
    //# - DeleteObjects MUST delete each of the corresponding instruction files using the default instruction file suffix.
    
    //= ../specification/s3-encryption/client.md#optional-api-operations
    //= type=exception
    //# - ReEncryptInstructionFile MAY be implemented by the S3EC.
    
    //= ../specification/s3-encryption/client.md#optional-api-operations
    //= type=exception
    //# - ReEncryptInstructionFile MAY be implemented by the S3EC.
    
    //= ../specification/s3-encryption/client.md#optional-api-operations
    //= type=exception
    //# - ReEncryptInstructionFile MAY be implemented by the S3EC.
    
    //= ../specification/s3-encryption/client.md#optional-api-operations
    //= type=exception
    //# - ReEncryptInstructionFile MUST re-encrypt the plaintext data key with a provided keyring.
    
    //= ../specification/s3-encryption/client.md#optional-api-operations
    //= type=exception
    //# - ReEncryptInstructionFile MUST decrypt the instruction file's encrypted data key for the given object using the client's CMM.
    
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
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        protected void PreInvoke(IExecutionContext executionContext)
        {
            ThrowIfRangeGet(executionContext);

            using (TelemetryUtilities.CreateSpan(EncryptionClient, Constants.SetupEncryptionHandlerSpanName, null, Amazon.Runtime.Telemetry.Tracing.SpanKind.CLIENT))
            {
#if NETFRAMEWORK
                var instructions = GenerateInstructions(executionContext);
#else
                var instructions = GenerateInstructionsAsync(executionContext).GetAwaiter().GetResult();
#endif
                //= ../specification/s3-encryption/client.md#required-api-operations
                //# - PutObject MUST be implemented by the S3EC.
                var putObjectRequest = executionContext.RequestContext.OriginalRequest as PutObjectRequest;
                if (putObjectRequest != null)
                {
                    //= ../specification/s3-encryption/client.md#required-api-operations
                    //# - PutObject MUST encrypt its input data before it is uploaded to S3.
#if NETFRAMEWORK
                    EncryptObject(instructions, putObjectRequest);
#else
                    EncryptObjectAsync(instructions, putObjectRequest).GetAwaiter().GetResult();
#endif
                }

                PreInvokeSynchronous(executionContext, instructions);
            }
        }

#if NETFRAMEWORK
        private void EncryptObject(EncryptionInstructions instructions, PutObjectRequest putObjectRequest)
        {
            ValidateConfigAndMaterials();
            if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
            {
                GenerateEncryptedObjectRequestUsingMetadata(putObjectRequest, instructions);
            }
            else
            {
                var instructionFileRequest = GenerateEncryptedObjectRequestUsingInstructionFile(putObjectRequest, instructions);
                EncryptionClient.S3ClientForInstructionFile.PutObject(instructionFileRequest);
            }
        }
#endif

        /// <summary>
        /// Updates the request where the instruction file contains encryption information
        /// and the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="putObjectRequest">The request whose contents are to be encrypted.</param>
        /// <param name="instructions">EncryptionInstructions instructions used for creating encrypt stream</param>
        protected abstract PutObjectRequest GenerateEncryptedObjectRequestUsingInstructionFile(PutObjectRequest putObjectRequest, EncryptionInstructions instructions);

        /// <summary>
        /// Updates the request where the metadata contains encryption information
        /// and the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="putObjectRequest">The request whose contents are to be encrypted.</param>
        /// <param name="instructions">EncryptionInstructions instructions used for creating encrypt stream</param>
        protected abstract void GenerateEncryptedObjectRequestUsingMetadata(PutObjectRequest putObjectRequest, EncryptionInstructions instructions);

#if NETFRAMEWORK
        /// <summary>
        /// Generate encryption instructions
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <returns>EncryptionInstructions to be used for encryption</returns>
        protected abstract EncryptionInstructions GenerateInstructions(IExecutionContext executionContext);
#endif

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <typeparam name="T">The response type for the current request.</typeparam>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public override async System.Threading.Tasks.Task<T> InvokeAsync<T>(IExecutionContext executionContext)
        {
            await PreInvokeAsync(executionContext).ConfigureAwait(false);
            return await base.InvokeAsync<T>(executionContext).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypts the S3 object being uploaded.
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        protected async System.Threading.Tasks.Task PreInvokeAsync(IExecutionContext executionContext)
        {
            ThrowIfRangeGet(executionContext);
            using (TelemetryUtilities.CreateSpan(EncryptionClient, Constants.SetupEncryptionHandlerSpanName, null, Amazon.Runtime.Telemetry.Tracing.SpanKind.CLIENT))
            {
                EncryptionInstructions instructions = await GenerateInstructionsAsync(executionContext).ConfigureAwait(false);

                var request = executionContext.RequestContext.OriginalRequest;

                var putObjectRequest = request as PutObjectRequest;
                if (putObjectRequest != null)
                {
                    await EncryptObjectAsync(instructions, putObjectRequest).ConfigureAwait(false);
                }

                PreInvokeSynchronous(executionContext, instructions);
            }
        }

        private async System.Threading.Tasks.Task EncryptObjectAsync(EncryptionInstructions instructions, PutObjectRequest putObjectRequest)
        {
            ValidateConfigAndMaterials();
            if (EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata)
            {
                GenerateEncryptedObjectRequestUsingMetadata(putObjectRequest, instructions);
            }
            else
            {
                var instructionFileRequest = GenerateEncryptedObjectRequestUsingInstructionFile(putObjectRequest, instructions);
                await EncryptionClient.S3ClientForInstructionFile.PutObjectAsync(instructionFileRequest)
                    .ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Generate encryption instructions asynchronously
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        /// <returns>EncryptionInstructions to be used for encryption</returns>
        protected abstract System.Threading.Tasks.Task<EncryptionInstructions> GenerateInstructionsAsync(IExecutionContext executionContext);

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

        internal void PreInvokeSynchronous(IExecutionContext executionContext, EncryptionInstructions instructions)
        {
            var request = executionContext.RequestContext.OriginalRequest;

            var useKMSKeyWrapping = this.EncryptionClient.EncryptionMaterials.KMSKeyID != null;
            var initiateMultiPartUploadRequest = request as InitiateMultipartUploadRequest;
            if (initiateMultiPartUploadRequest != null)
            {
                GenerateInitiateMultiPartUploadRequest(instructions, initiateMultiPartUploadRequest, useKMSKeyWrapping);
            }

            //= ../specification/s3-encryption/client.md#optional-api-operations
            //# - UploadPart MAY be implemented by the S3EC.
            var uploadPartRequest = request as UploadPartRequest;
            if (uploadPartRequest != null)
            {
                GenerateEncryptedUploadPartRequest(uploadPartRequest);
            }
        }
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //= type=implication
        //# - Each part MUST be encrypted using the same cipher instance for each part.
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //# - UploadPart MUST encrypt each part.
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //# - Each part MUST be encrypted in sequence.
        
        /// <summary>
        /// Updates the request where the input stream contains the encrypted object contents.
        /// </summary>
        /// <param name="uploadPartRequest">UploadPartRequest whose input stream needs to updated</param>
        protected abstract void GenerateEncryptedUploadPartRequest(UploadPartRequest uploadPartRequest);
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //# - CreateMultipartUpload MAY be implemented by the S3EC.
        
        //= ../specification/s3-encryption/client.md#optional-api-operations
        //# - If implemented, CreateMultipartUpload MUST initiate a multipart upload.
        
        /// <summary>
        /// Update InitiateMultipartUploadRequest request with given encryption instructions
        /// </summary>
        /// <param name="instructions">EncryptionInstructions which used for encrypting the UploadPartRequest request</param>
        /// <param name="initiateMultiPartUploadRequest">InitiateMultipartUploadRequest whose encryption context needs to updated</param>
        /// <param name="useKmsKeyWrapping">If true, KMS mode of encryption is used</param>
        protected abstract void GenerateInitiateMultiPartUploadRequest(EncryptionInstructions instructions, InitiateMultipartUploadRequest initiateMultiPartUploadRequest, bool useKmsKeyWrapping);

        /// <summary>
        /// Make sure that the storage mode and encryption materials are compatible.
        /// The client only supports KMS key wrapping in metadata storage mode.
        /// </summary>
        internal void ValidateConfigAndMaterials()
        {
            var usingKMSKeyWrapping = this.EncryptionClient.EncryptionMaterials.KMSKeyID != null;
            var usingMetadataStorageMode = EncryptionClient.S3CryptoConfig.StorageMode == CryptoStorageMode.ObjectMetadata;
            if (usingKMSKeyWrapping && !usingMetadataStorageMode)
                throw new AmazonClientException($"{EncryptionClient.GetType().Name} only supports KMS key wrapping in metadata storage mode. " +
                    "Please set StorageMode to CryptoStorageMode.ObjectMetadata or refrain from using KMS EncryptionMaterials.");
        }

        /// <summary>
        /// Throws an exception if attempting a range GET with an encryption client
        /// </summary>
        /// <param name="executionContext">The execution context, it contains the request and response context.</param>
        internal void ThrowIfRangeGet(IExecutionContext executionContext)
        {
            var getObjectRequest = executionContext.RequestContext.OriginalRequest as GetObjectRequest;
            if (getObjectRequest != null && getObjectRequest.ByteRange != null)
            {
                //= ../specification/s3-encryption/decryption.md#ranged-gets
                //= type=exception
                //# The S3EC MAY support the "range" parameter on GetObject which specifies a subset of bytes to download and decrypt.
                
                //= ../specification/s3-encryption/decryption.md#ranged-gets
                //= type=exception
                //# If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning and end of the cipher blocks for the given range.
                
                //= ../specification/s3-encryption/decryption.md#ranged-gets
                //= type=exception
                //# If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.
                
                //= ../specification/s3-encryption/decryption.md#ranged-gets
                //= type=exception
                //# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.
                
                //= ../specification/s3-encryption/decryption.md#ranged-gets
                //= type=exception
                //# If the GetObject response contains a range, but the GetObject request does not contain a range, the S3EC MUST throw an exception.
                throw new NotSupportedException("Unable to perform range get request: Range get is not supported. " +
                                               $"See {EncryptionUtils.SDKEncryptionDocsUrl}");
            }
        }
    }
}
