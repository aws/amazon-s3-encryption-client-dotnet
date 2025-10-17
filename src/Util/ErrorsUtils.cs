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

namespace Amazon.Extensions.S3.Encryption.Util
{
    public static class ErrorsUtils
    {
        private const string ECMissMatchedException =
            "Provided encryption context does not match information retrieved from S3";

        private const string ECNotSupported =
            "Encryption context is only supported for KMS encryption material from V2.";

        private const string ECContainsReservedKeyV2 =
            "Conflict in reserved KMS Encryption Context key " + EncryptionUtils.XAmzEncryptionContextCekAlg + ". " +
            "This value is reserved for the S3 Encryption Client and cannot be set by the user.";
        
        private const string MultipleECOnEncryptPath =
            "Encryption context should be set on either client or request.";
        
        // This exception is thrown when EC is passed when using non KMS material and on encrypt path of V1 S3EC client. 
        internal static void ThrowECNotSupported()
        {
            throw new ArgumentException(ECNotSupported);
        }
        
        // Encryption Context is validated client side with the object's metadata before passing to KMS.
        // This exception is thrown when EC validation in client side is failed.
        internal static void ThrowECMissMatchedException()
        {
            throw new AmazonS3EncryptionClientException(ECMissMatchedException);
        }
        
        // Encryption Context in V2 Materials contains a reserved key `EncryptionUtils.XAmzEncryptionContextCekAlg`.
        // This exception is thrown when user includes reserved key in the EC.
        internal static void ThrowECContainsReservedKeyV2()
        {
            throw new ArgumentException(ECContainsReservedKeyV2);
        }
        
        // Encryption Context is only supported in one path -- either client or request.
        // This exception is thrown when EC is passed in both client and request.
        internal static void ThrowMultipleECOnEncryptPath()
        {
            throw new ArgumentException(MultipleECOnEncryptPath);
        }
    }
}