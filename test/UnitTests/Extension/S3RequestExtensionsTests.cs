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

namespace Amazon.Extensions.S3.Encryption.UnitTests.Extension
{
    public class S3RequestExtensionsTests
    {
        [Fact]
        public void SetEncryptionContext_StoresContextCorrectly()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            putObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            getObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.RequestEC1);
            
            var retrievedECForPut = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var retrievedECForGet = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var retrievedECForInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            // Reserved keys are only added when client performs API requests
            Assert.False(retrievedECForPut.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg));
            
            Assert.True(retrievedECForPut.ContainsKey(TestConstants.RequestEC1Key));
            Assert.Equal(TestConstants.RequestEC1Value, retrievedECForPut[TestConstants.RequestEC1Key]);
            
            Assert.Equal(retrievedECForPut, TestConstants.RequestEC1);
            Assert.Equal(retrievedECForPut, retrievedECForGet);
            Assert.Equal(retrievedECForGet, retrievedECForInitMPU);
        }

        [Fact]
        public void GetEncryptionContext_ReturnsNullWhenNotSet()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();

            var retrievedECForPut = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var retrievedECForGet = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var retrievedECForInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);

            Assert.Null(retrievedECForPut);
            Assert.Null(retrievedECForGet);
            Assert.Null(retrievedECForInitMPU);
        }

        [Fact]
        public void SetEncryptionContext_WithReservedKey_DoesNotThrowsArgumentException()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            // Does not throw exception as putObjectRequest is not associated with client. 
            // throws exception if it is used with V2 client
            putObjectRequest.SetEncryptionContext(TestConstants.EncryptionContextWithReservedKey);
            getObjectRequest.SetEncryptionContext(TestConstants.EncryptionContextWithReservedKey);
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.EncryptionContextWithReservedKey);
        }

        [Fact]
        public void SetEncryptionContext_MultipleCalls_ReplacesContext()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            var firstEncryptionContext = new Dictionary<string, string> { { "first", "value1" } };
            var secondEncryptionContext = new Dictionary<string, string> { { "second", "value2" } };
            
            // set EC
            putObjectRequest.SetEncryptionContext(firstEncryptionContext);
            getObjectRequest.SetEncryptionContext(firstEncryptionContext);
            initiateMultipartUploadRequest.SetEncryptionContext(firstEncryptionContext);
            
            // replace EC
            putObjectRequest.SetEncryptionContext(secondEncryptionContext);
            getObjectRequest.SetEncryptionContext(secondEncryptionContext);
            initiateMultipartUploadRequest.SetEncryptionContext(secondEncryptionContext);
            
            var retrievedECForPut = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var retrievedECForGet = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var retrievedECForInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            Assert.NotNull(retrievedECForPut);
            Assert.False(retrievedECForPut.ContainsKey("first"));
            Assert.Equal("value2", retrievedECForPut["second"]);
            
            Assert.Equal(retrievedECForPut, retrievedECForGet);
            Assert.Equal(retrievedECForGet, retrievedECForInitMPU);
        }

        [Fact]
        public void SetEncryptionContext_DoesNotModifyOriginalDictionary()
        {
            // Internally, S3EC adds reserved key-value pair to the encryption context.
            // This test ensures encryption context passed by the user is not modified on users end
            // and is only modified internally.
            
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();

            putObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            Assert.False(TestConstants.RequestEC1.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg));
            
            getObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            Assert.False(TestConstants.RequestEC1.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg));
            
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.RequestEC1);
            Assert.False(TestConstants.RequestEC1.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg));
        }

        [Fact]
        public void SetEncryptionContext_WithEmptyDictionary()
        {
            var putObjectRequest = new PutObjectRequest();
            var getObjectRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            
            var emptyEncryptionContext = new Dictionary<string, string>();
            
            putObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            getObjectRequest.SetEncryptionContext(TestConstants.RequestEC1);
            initiateMultipartUploadRequest.SetEncryptionContext(TestConstants.RequestEC1);
            
            putObjectRequest.SetEncryptionContext(emptyEncryptionContext);
            getObjectRequest.SetEncryptionContext(emptyEncryptionContext);
            initiateMultipartUploadRequest.SetEncryptionContext(emptyEncryptionContext);
            
            var retrievedECForPut = EncryptionContextUtils.GetEncryptionContextFromRequest(putObjectRequest);
            var retrievedECForGet = EncryptionContextUtils.GetEncryptionContextFromRequest(getObjectRequest);
            var retrievedECForInitMPU = EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);
            
            Assert.NotNull(retrievedECForPut);
            Assert.Empty(retrievedECForPut);
            
            Assert.Equal(retrievedECForPut, retrievedECForGet);
            Assert.Equal(retrievedECForGet, retrievedECForInitMPU);
        }

        [Fact]
        public void SetEncryptionContext_WithDifferentRequestTypes_WorksCorrectly()
        {
            var putRequest = new PutObjectRequest();
            var getRequest = new GetObjectRequest();
            var initiateMultipartUploadRequest = new InitiateMultipartUploadRequest();
            var context1 = new Dictionary<string, string> { { "key1", "value1" } };
            var context2 = new Dictionary<string, string> { { "key2", "value2" } };
            var context3 = new Dictionary<string, string> { { "key3", "value3" } };
            
            putRequest.SetEncryptionContext(context1);
            getRequest.SetEncryptionContext(context2);
            initiateMultipartUploadRequest.SetEncryptionContext(context3);
            
            var putResult = EncryptionContextUtils.GetEncryptionContextFromRequest(putRequest);
            var getResult = EncryptionContextUtils.GetEncryptionContextFromRequest(getRequest);
            var initMultipartResult = 
                EncryptionContextUtils.GetEncryptionContextFromRequest(initiateMultipartUploadRequest);

            Assert.True(putResult.ContainsKey("key1"));
            Assert.False(putResult.ContainsKey("key2"));
            Assert.False(putResult.ContainsKey("key3"));
            Assert.False(getResult.ContainsKey("key1"));
            Assert.True(getResult.ContainsKey("key2"));
            Assert.False(getResult.ContainsKey("key3"));
            Assert.False(initMultipartResult.ContainsKey("key1"));
            Assert.False(initMultipartResult.ContainsKey("key2"));
            Assert.True(initMultipartResult.ContainsKey("key3"));
            
            Assert.Equal("value1", putResult["key1"]);
            Assert.Equal("value2", getResult["key2"]);
            Assert.Equal("value3", initMultipartResult["key3"]);
        }
    }
}
