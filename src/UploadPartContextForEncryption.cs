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

using System.IO;
using Amazon.Extensions.S3.Encryption.Util;

namespace Amazon.Extensions.S3.Encryption
{
    // Note: this class for context of encryption and is not related to AWS KMS Encryption Context
    internal class UploadPartEncryptionContext
    {
        public CryptoStorageMode StorageMode { get; set; }
        public byte[] EncryptedEnvelopeKey { get; set; }
        public byte[] EnvelopeKey { get; set; }
        public byte[] FirstIV { get; set; }
        public byte[] NextIV { get; set; }
        public bool IsFinalPart { get; set; }
        public int? PartNumber { get; set; }
        public byte[] KeyCommitment { get; set; }

        /// <summary>
        /// Content encryption algorithm used for upload part
        /// </summary>
        public AlgorithmSuite AlgorithmSuite { get; set; }

        /// <summary>
        /// Key encryption algorithm used for upload part
        /// </summary>
        public string WrapAlgorithm { get; set; }

        /// <summary>
        /// Keep track of the AES GCM stream instance
        /// Reinitializing the stream for every upload part will re-calculate the tag
        /// which will corrupt the data
        /// </summary>
        public Stream CryptoStream { get; set; }
    }
}

