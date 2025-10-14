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

namespace Amazon.Extensions.S3.Encryption.Tests.Common
{
    public static class TestConstants
    {
        public static readonly string RequestEC1Key = "request1";
        public static readonly string RequestEC2Key = "request2";
        public static readonly string FallbackECKey = "fallback";
        public static readonly string RequestEC1Value = "requestValue1";
        public static readonly string RequestEC2Value = "requestValue2";
        public static readonly string FallbackECValue = "fallbackValue";
        public static readonly string XAmzEncryptionContextCekAlg = "aws:x-amz-cek-alg";
        public static readonly string XAmzAesCbcPaddingCekAlgValue = "AES/CBC/PKCS5Padding";
        public static readonly string XAmzAesGcmCekAlgValue = "AES/GCM/NoPadding";
        public static readonly string XAmzMatDesc = "x-amz-matdesc";
        public static readonly string XAmzKeyV2 = "x-amz-key-v2";
        public static readonly string ECNotSupported =
            "Encryption context is only supported for KMS encryption material from V2.";

        public static readonly string ECNotMatched =
            "Provided encryption context does not match information retrieved from S3";

        public static readonly string ReservedKeyInECErrorMessage =
            $"Conflict in reserved KMS Encryption Context key {XAmzEncryptionContextCekAlg}. " +
            "This value is reserved for the S3 Encryption Client and cannot be set by the user.";

        public static readonly string MultipleECErrorMesage =
            "Encryption context should be set on either client or request.";
        public static readonly Dictionary<string, string> RequestEC1 = 
            new Dictionary<string, string> { { RequestEC1Key, RequestEC1Value } };
        public static readonly Dictionary<string, string> RequestEC2 = 
            new Dictionary<string, string> { { RequestEC2Key, RequestEC2Value } };
        public static readonly Dictionary<string, string> FallbackEC = 
            new Dictionary<string, string> { { FallbackECKey, FallbackECValue } };
        
        public static Dictionary<string, string> EncryptionContextWithReservedKey = new Dictionary<string, string>
        {
            { XAmzEncryptionContextCekAlg, RequestEC1Value }
        };
    }
}
