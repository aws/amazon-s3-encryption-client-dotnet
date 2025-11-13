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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Amazon.Extensions.S3.Encryption.Util;
using System.Threading.Tasks;
using Amazon.Extensions.S3.Encryption.Extensions;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.Tests.Common
{
    public static class CommonUtils
    {
        public static void ValidateMaterialDescription(GetObjectResponse response, Dictionary<string, string> expectedMatDesc)
        {                                                                                                                                                                                                                                                                                                                                                                                  
            Assert.NotNull(response.Metadata[TestConstants.XAmzMatDesc]);                                                                                                                                                                                                                                                                                                                   
            string matDesc = response.Metadata[TestConstants.XAmzMatDesc];                                                                                                                                                                                                                                                                                                                           
            var actualMatDesc = JsonSerializer.Deserialize<Dictionary<string, string>>(matDesc);                                                                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                                                                                                                                                                           
            Assert.Equal(expectedMatDesc.Count, actualMatDesc.Count);                                                                                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                                                                                                                                           
            foreach (var kvp in expectedMatDesc)                                                                                                                                                                                                                                                                                                                                           
            {                                                                                                                                                                                                                                                                                                                                                                              
                Assert.True(actualMatDesc.ContainsKey(kvp.Key));                                                                                                                                                                                                                                                                                                                           
                Assert.Equal(kvp.Value, actualMatDesc[kvp.Key]);                                                                                                                                                                                                                                                                                                     
            }
        }
        
        public static async Task DecryptDataKeyWithoutS3ECAsync(string key, AmazonS3Client s3Client, string bucketName,
            string encryptionDataKeyLocation, Dictionary<string, string> ECToKMS = null, Dictionary<string, string> requestEC = null)
        {
            var getObjectResponse = await CommonUtils.MakeGetObjectAsyncCall(s3Client, bucketName, key, requestEC);
            
            var kmsClient = new AmazonKeyManagementServiceClient();
            var encryptedKey = getObjectResponse.Metadata[encryptionDataKeyLocation];
            var decryptRequest = new DecryptRequest
            {
                CiphertextBlob = new MemoryStream(Convert.FromBase64String(encryptedKey)),
                EncryptionContext = ECToKMS
            };
            
            // Decrypt will fail ECToKMS is incorrect
            await kmsClient.DecryptAsync(decryptRequest);
        }
        
        public static async Task<GetObjectResponse> MakeGetObjectAsyncCall(AmazonS3Client s3Client, string bucketName, string key, 
            Dictionary<string, string> requestEC = null)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };
            if (requestEC != null)
            {
                getObjectRequest.SetEncryptionContext(requestEC);
            }
            
            var getObjectResponse = await s3Client.GetObjectAsync(getObjectRequest).ConfigureAwait(false);
            
            return getObjectResponse;
        }
#if NETFRAMEWORK
        public static void DecryptDataKeyWithoutS3EC(string key, AmazonS3Client s3Client, string bucketName,
            string encryptionDataKeyLocation, Dictionary<string, string> ECToKMS = null, Dictionary<string, string> requestEC = null)
        {
            var getObjectResponse = MakeGetObjectCall(s3Client, bucketName, key, requestEC);
            
            var kmsClient = new AmazonKeyManagementServiceClient();
            var encryptedKey = getObjectResponse.Metadata[encryptionDataKeyLocation];
            var decryptRequest = new DecryptRequest
            {
                CiphertextBlob = new MemoryStream(Convert.FromBase64String(encryptedKey)),
                EncryptionContext = ECToKMS
            };
            
            // Decrypt will fail ECToKMS is incorrect
            kmsClient.Decrypt(decryptRequest);
        }
        
        public static GetObjectResponse MakeGetObjectCall(AmazonS3Client s3Client, string bucketName, string key, 
            Dictionary<string, string> requestEC = null)
        {
            GetObjectRequest getObjectRequest = new GetObjectRequest
            {
                BucketName = bucketName,
                Key = key
            };
            if (requestEC != null)
            {
                getObjectRequest.SetEncryptionContext(requestEC);
            }
            
            var getObjectResponse = s3Client.GetObject(getObjectRequest);
            
            return getObjectResponse;
        }
#endif
    }
}