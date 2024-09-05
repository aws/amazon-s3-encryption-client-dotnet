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
using System.Text;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Exception thrown by the SDK for errors that occur within the SDK for crypto operations.
    /// </summary>
#if !PCL && NETFRAMEWORK
    [Serializable]
#endif
    public class AmazonCryptoException : Exception
    {
        public AmazonCryptoException(string message) : base(message) { }

        public AmazonCryptoException(string message, Exception innerException) : base(message, innerException) { }
    }
}
