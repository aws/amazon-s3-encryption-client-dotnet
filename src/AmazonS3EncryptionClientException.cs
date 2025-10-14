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

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Exception thrown by the S3EC for errors that occur within S3EC that are generic enough to be classified.
    /// </summary>
#if !PCL && NETFRAMEWORK
    [Serializable]
#endif
    public class AmazonS3EncryptionClientException: Exception
    {
        public AmazonS3EncryptionClientException(string message) : base(message) { }

        public AmazonS3EncryptionClientException(string message, Exception innerException) : base(message, innerException) { }
    }
}