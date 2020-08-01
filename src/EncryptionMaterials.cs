﻿/*
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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// The "key encrypting key" materials used in encrypt/decryption.
    /// These materials may be an asymmetric key, a symmetric key, or a KMS key ID.
    /// </summary>
    public class EncryptionMaterials : EncryptionMaterialsBase
    {
        /// <inheritdoc />
        public EncryptionMaterials(AsymmetricAlgorithm algorithm) : base(algorithm)
        {
        }

        /// <inheritdoc />
        public EncryptionMaterials(SymmetricAlgorithm algorithm) : base(algorithm)
        {
        }

        /// <inheritdoc />
        public EncryptionMaterials(string kmsKeyID) : base(kmsKeyID)
        {
            MaterialsDescription.Add(EncryptionUtils.KMSCmkIDKey, kmsKeyID);
        }
    }
}
