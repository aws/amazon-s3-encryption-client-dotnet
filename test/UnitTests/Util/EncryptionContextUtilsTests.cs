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

using System.Collections.Generic;
using Amazon.Extensions.S3.Encryption.Extensions;
using Amazon.Extensions.S3.Encryption.Tests.Common;
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.S3.Model;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests.Util
{
    public class EncryptionContextUtilsTests
    {
        [Fact]
        public void ValidateNoEncryptionContextForNonKMS_ThrowsWhenContextExists()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            putObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            getObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.RequestEC1);
            
            var mockExecutionContextPutObject = Utils.CreateMockExecutionContext(putObjectRequest);
            var mockExecutionContextGetObject = Utils.CreateMockExecutionContext(getObjectRequest);
            var mockExecutionContextInitMPU = Utils.CreateMockExecutionContext(initiateMultipartUploadRequest);
            
            var exceptionPutObject = Assert.Throws<System.ArgumentException>(() => 
                EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextPutObject.Object));
            var exceptionGetObject = Assert.Throws<System.ArgumentException>(() => 
                EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextGetObject.Object));
            var exceptionInitMPU = Assert.Throws<System.ArgumentException>(() => 
                EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextInitMPU.Object));
            
            Assert.Contains("Encryption context is only supported for KMS encryption material from V2.", exceptionPutObject.Message);
            Assert.Equal(exceptionPutObject.Message, exceptionGetObject.Message);
            Assert.Equal(exceptionGetObject.Message, exceptionInitMPU.Message);
        }
        
        [Fact]
        public void ValidateNoEncryptionContextForNonKMS_DoesNotThrowWhenContextIsNull()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            var mockExecutionContextPutObject = Utils.CreateMockExecutionContext(putObjectRequest);
            var mockExecutionContextGetObject = Utils.CreateMockExecutionContext(getObjectRequest);
            var mockExecutionContextInitMPU = Utils.CreateMockExecutionContext(initiateMultipartUploadRequest);

            EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextPutObject.Object);
            EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextGetObject.Object);
            EncryptionContextUtils.ValidateNoEncryptionContextForNonKMS(mockExecutionContextInitMPU.Object);
        }

        [Fact]
        public void GetEncryptionContextFromRequest_ReturnsECFromRequest()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            putObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            getObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.RequestEC1);

            var ecPutObject = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var ecGetObject = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var ecInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            Assert.True(ecPutObject.ContainsKey(TestConstants.RequestEC1Key));
            Assert.Equal(TestConstants.RequestEC1Value, ecPutObject[TestConstants.RequestEC1Key]);
            Assert.Equal(ecPutObject, ecGetObject);
            Assert.Equal(ecGetObject, ecInitMPU);
        }
        
        [Fact]
        public void GetEncryptionContextFromRequest_WhenSetNothingReturnsNull()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();

            var exceptionPutObject = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var exceptionGetObject = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var exceptionInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            Assert.Null(exceptionPutObject);
            Assert.Null(exceptionGetObject);
            Assert.Null(exceptionInitMPU);
        }
        
        [Fact]
        public void GetEncryptionContextFromRequest_WhenSetNullReturnsNull()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            putObjectRequest.SetEncryptionContext(null);
            getObjectRequest.SetEncryptionContext(null);
            initiateMultipartUploadRequest.SetEncryptionContext(null);

            var exceptionPutObject = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var exceptionGetObject = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var exceptionInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            Assert.Null(exceptionPutObject);
            Assert.Null(exceptionGetObject);
            Assert.Null(exceptionInitMPU);
        }

        [Fact]
        public void ValidateEncryptionContext_DoesNotThrowWhenContextsExactMatch()
        {
            EncryptionContextUtils.ValidateEncryptionContext(TestConstants.RequestEC1, TestConstants.RequestEC1);
        }
        
        [Fact]
        public void ValidateEncryptionContext_ThrowsWhenCompleteMismatched()
        {
            var exception = Assert.Throws<AmazonS3EncryptionClientException>(() => 
                EncryptionContextUtils.ValidateEncryptionContext(TestConstants.RequestEC1, TestConstants.RequestEC2));
            
            Assert.Contains("Provided encryption context does not match information retrieved from S3", exception.Message);
        }

        [Fact]
        public void ValidateEncryptionContext_ThrowsWhenEffectiveHasMoreKeys()
        {
            var effectiveEC = new Dictionary<string, string> { { "key1", "value1" }, { "key2", "value2" } };
            var metadataEC = new Dictionary<string, string> { { "key1", "value1" } };

            var exception = Assert.Throws<AmazonS3EncryptionClientException>(() => 
                EncryptionContextUtils.ValidateEncryptionContext(effectiveEC, metadataEC));
            
            Assert.Contains("Provided encryption context does not match information retrieved from S3", exception.Message);
        }

        [Fact]
        public void ValidateEncryptionContext_ThrowsWhenMetadataHasMoreKeys()
        {
            var effectiveEC = new Dictionary<string, string> { { "key1", "value1" } };
            var metadataEC = new Dictionary<string, string> { { "key1", "value1" }, { "key2", "value2" } };

            var exception = Assert.Throws<AmazonS3EncryptionClientException>(() => 
                EncryptionContextUtils.ValidateEncryptionContext(effectiveEC, metadataEC));
            
            Assert.Contains("Provided encryption context does not match information retrieved from S3", exception.Message);
        }

        [Fact]
        public void ValidateEncryptionContext_ThrowsWhenValueMismatch()
        {
            var effectiveEC = new Dictionary<string, string> { { "key1", "value1" } };
            var metadataEC = new Dictionary<string, string> { { "key1", "wrongvalue" } };

            var exception = Assert.Throws<AmazonS3EncryptionClientException>(() => 
                EncryptionContextUtils.ValidateEncryptionContext(effectiveEC, metadataEC));
            
            Assert.Contains("Provided encryption context does not match information retrieved from S3", exception.Message);
        }
        
        [Fact]
        public void ValidateEncryptionContext_ThrowsWhenKeyMismatch()
        {
            var effectiveEC = new Dictionary<string, string> { { "key1", "value1" } };
            var metadataEC = new Dictionary<string, string> { { "key2", "value1" } };

            var exception = Assert.Throws<AmazonS3EncryptionClientException>(() => 
                EncryptionContextUtils.ValidateEncryptionContext(effectiveEC, metadataEC));
            
            Assert.Contains("Provided encryption context does not match information retrieved from S3", exception.Message);
        }
    }
}