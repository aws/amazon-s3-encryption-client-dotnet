/*
 * Copyright 2010-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
using System.Xml.Serialization;
using System.Text;
using System.IO;

using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.S3;

namespace Amazon.Extensions.S3.Encryption.Model
{
    /// <summary>
    /// Container for the parameters to the InitiateMultipartUpload operation.
    /// <para>Initiates a multipart upload and returns an upload ID.</para>
    /// </summary>
    public class InitiateMultipartUploadRequest : Amazon.S3.Model.InitiateMultipartUploadRequest
    {
        /// <summary>
        /// Envelope Key to Encrypt data
        /// </summary>
        internal byte[] EnvelopeKey { get; set; }

        /// <summary>
        /// Encrypted Envelope Key to Encrypt data
        /// </summary>
        internal byte[] EncryptedEnvelopeKey { get; set; }

        /// <summary>
        /// Initialization Vector for encryption
        /// </summary>
        internal byte[] IV { get; set; }

#if BCL || NETSTANDARD || NETCOREAPP3_1
        /// <summary>
        /// Storage mode for encryption information.
        /// </summary>
        internal Amazon.S3.Encryption.CryptoStorageMode StorageMode { get; set; }
#endif
    }
}
    
