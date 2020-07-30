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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Base class for EncryptionMaterials materials
    /// Encapsulates common properties and methods of the encryption materials
    /// </summary>
    public class EncryptionMaterialsBase
    {
        internal AsymmetricAlgorithm AsymmetricProvider { get; }

        internal SymmetricAlgorithm SymmetricProvider { get; }

        internal string KMSKeyID { get; }

        internal Dictionary<string, string> MaterialsDescription { get; }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing an asymmetric key.
        /// </summary>
        /// <param name="algorithm"></param>
        public EncryptionMaterialsBase(AsymmetricAlgorithm algorithm) : this(algorithm, null, null, new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a symmetric key.
        /// </summary>
        /// <param name="algorithm"></param>
        public EncryptionMaterialsBase(SymmetricAlgorithm algorithm) : this(null, algorithm, null, new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a KMS Key ID & material description used as encryption context to call KMS
        /// </summary>
        /// <param name="kmsKeyID">KmsContext customer master key</param>
        public EncryptionMaterialsBase(string kmsKeyID) : this(null, null, kmsKeyID, new Dictionary<string, string>())
        {
            if (string.IsNullOrEmpty(kmsKeyID))
            {
                throw new ArgumentNullException(nameof(kmsKeyID));
            }
        }

        internal EncryptionMaterialsBase(AsymmetricAlgorithm asymmetricAlgorithm, SymmetricAlgorithm symmetricAlgorithm, string kmsKeyID, Dictionary<string, string> materialsDescription)
        {
            AsymmetricProvider = asymmetricAlgorithm;
            SymmetricProvider = symmetricAlgorithm;
            KMSKeyID = kmsKeyID;
            MaterialsDescription = materialsDescription;
        }
    }
}
