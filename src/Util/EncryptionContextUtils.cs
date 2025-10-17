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
using Amazon.Runtime;
using Amazon.Runtime.Internal;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal class EncryptionContextUtils
    {
        internal static void ThrowIfECContainsReservedKeysForV2Client(Dictionary<string, string> encryptionContext)
        {
            if (encryptionContext.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg))
            {
                ErrorsUtils.ThrowECContainsReservedKeyV2();
            }
        }
        
        internal static void ValidateNoEncryptionContextForNonKMS(IExecutionContext executionContext)
        {
            var ecFromRequest = GetEncryptionContextFromRequest(executionContext.RequestContext.OriginalRequest);
            if (ecFromRequest != null)
            {
                ErrorsUtils.ThrowECNotSupported();
            }
        }
        
        internal static Dictionary<string, string> GetEncryptionContextFromRequest(IAmazonWebServiceRequest internalRequest)
        {
            if (internalRequest.RequestState.TryGetValue(Constants.S3ECPerRequestEncryptionContext, out var ec) && ec != null)                                                                                                     
            {                                                                         
                // Return a copy to prevent from modifying the original RequestState dictionary
                return new Dictionary<string, string>((Dictionary<string, string>)ec);
            }
            return null;
        }

        internal static void ValidateEncryptionContext(Dictionary<string, string> effectiveEC, Dictionary<string, string> ecFromMetaData)
        {
            if (effectiveEC.Count != ecFromMetaData.Count) 
                ErrorsUtils.ThrowECMissMatchedException();
            
            foreach (var kvp in effectiveEC)
            {
                if (!ecFromMetaData.TryGetValue(kvp.Key, out var value) || value != kvp.Value)
                    ErrorsUtils.ThrowECMissMatchedException();
            }
        }
    }
}