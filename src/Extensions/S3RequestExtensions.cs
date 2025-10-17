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
using Amazon.Extensions.S3.Encryption.Util;
using Amazon.Runtime.Internal;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Extensions
{
    public static class S3RequestExtensions
    {
        public static void SetEncryptionContext(this PutObjectRequest request, Dictionary<string,string> encryptionContext)
        {
            SetEncryptionContextInternal(request, encryptionContext);
        }

        public static void SetEncryptionContext(this GetObjectRequest request, Dictionary<string,string> encryptionContext)
        {
            SetEncryptionContextInternal(request, encryptionContext);
        }
        
        public static void SetEncryptionContext(this InitiateMultipartUploadRequest request, Dictionary<string,string> encryptionContext)
        {                                                                                                                                                                                                                
            SetEncryptionContextInternal(request, encryptionContext);                                                                                                                                                    
        } 
        
        private static void SetEncryptionContextInternal(IAmazonWebServiceRequest request, Dictionary<string,string> encryptionContext)
        {
            request.RequestState[Constants.S3ECPerRequestEncryptionContext] = encryptionContext;
        }
    }
}