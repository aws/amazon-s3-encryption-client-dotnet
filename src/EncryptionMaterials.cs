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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// The "key encrypting key" materials used in encrypt/decryption.
    /// These materials may be an asymmetric key, a symmetric key, or a KMS key ID.
    /// </summary>
    public class EncryptionMaterials
    {
        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing an asymmetric key.
        /// </summary>
        /// <param name="algorithm"></param>
        public EncryptionMaterials(AsymmetricAlgorithm algorithm) : this(algorithm, null, null, new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a symmetric key.
        /// </summary>
        /// <param name="algorithm"></param>
        public EncryptionMaterials(SymmetricAlgorithm algorithm) : this(null, algorithm, null, new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a KMS Key ID & empty material description used as encryption context to call KMS
        /// </summary>
        /// <param name="kmsKeyID">Symmetric customer master key</param>
        public EncryptionMaterials(string kmsKeyID) : this(kmsKeyID, new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a KMS Key ID & material description used as encryption context to call KMS
        /// </summary>
        /// <param name="kmsKeyID">Symmetric customer master key</param>
        /// <param name="materialsDescription">Encryption context for KMS</param>
        public EncryptionMaterials(string kmsKeyID, Dictionary<string, string> materialsDescription) : this(null, null, kmsKeyID, materialsDescription)
        {
            materialsDescription.Add(EncryptionUtils.KMSCmkIDKey, kmsKeyID);
        }

        private EncryptionMaterials(AsymmetricAlgorithm asymmetricAlgorithm, SymmetricAlgorithm symmetricAlgorithm, string kmsKeyID, Dictionary<string, string> materialsDescription)
        {
            AsymmetricProvider = asymmetricAlgorithm;
            SymmetricProvider = symmetricAlgorithm;
            KMSKeyID = kmsKeyID;
            MaterialsDescription = materialsDescription;

            if (MaterialsDescription.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg))
            {
                throw new ArgumentException($"{EncryptionUtils.XAmzEncryptionContextCekAlg} already exists." +
                                            $"{EncryptionUtils.XAmzEncryptionContextCekAlg} is an AWS reserved key and must not be used for KMS encryption context.");
            }
        }

        internal AsymmetricAlgorithm AsymmetricProvider { get; }

        internal SymmetricAlgorithm SymmetricProvider { get; }

        internal string KMSKeyID { get; }

        internal Dictionary<string, string> MaterialsDescription { get; }
    }
}
