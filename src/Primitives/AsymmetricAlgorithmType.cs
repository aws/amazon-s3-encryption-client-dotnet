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

namespace Amazon.Extensions.S3.Encryption.Primitives
{
    /// <summary>
    /// Type of public key and private key pair based crypto algorithms
    /// </summary>
    public enum AsymmetricAlgorithmType
    {
        /// <summary>
        /// RSA encryption using OAEP padding
        /// SHA-1 as the hash for MGF1 &amp; OAEP
        /// </summary>
        RsaOaepSha1
    }
}