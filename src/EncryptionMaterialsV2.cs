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
using Amazon.Extensions.S3.Encryption.Primitives;
using Amazon.Extensions.S3.Encryption.Util;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// The "key encrypting key" materials used in encrypt/decryption.
    /// These materials may be an asymmetric key, a symmetric key, or a KMS key ID.
    /// Every material has its unique type such as RsaOaepSha1, AesGcm or KmsContext respectively.
    /// </summary>
    public class EncryptionMaterialsV2 : EncryptionMaterialsBase
    {
        /// <summary>
        /// Type of of the asymmetric algorithm
        /// </summary>
        internal SymmetricAlgorithmType SymmetricProviderType { get; }

        /// <summary>
        /// Type of of the asymmetric algorithm
        /// </summary>
        internal AsymmetricAlgorithmType AsymmetricProviderType { get; }

        /// <summary>
        /// Type of the KMS Id
        /// </summary>
        internal KmsType KmsType { get; }
        
        /// <summary>
        /// This is the default material description if user provides nothing
        /// This contains the reserved keys in Encryption Materials V2
        /// </summary>
        internal static readonly Dictionary<string, string> DefaultMaterialsDescription = 
            new Dictionary<string, string> { [EncryptionUtils.XAmzEncryptionContextCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue };

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing an asymmetric key.
        /// </summary>
        /// <param name="algorithm">Generic asymmetric algorithm</param>
        /// <param name="algorithmType">Type of of the asymmetric algorithm</param>
        public EncryptionMaterialsV2(AsymmetricAlgorithm algorithm, AsymmetricAlgorithmType algorithmType) : base(algorithm)
        {
            AsymmetricProviderType = algorithmType;
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a symmetric key.
        /// </summary>
        /// <param name="algorithm">Generic symmetric algorithm</param>
        /// <param name="algorithmType">Type of the symmetric algorithm</param>
        public EncryptionMaterialsV2(SymmetricAlgorithm algorithm, SymmetricAlgorithmType algorithmType) : base(algorithm)
        {
            SymmetricProviderType = algorithmType;
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a KMS Key ID
        /// </summary>
        /// <param name="kmsKeyId">Generic KMS Id</param>
        /// <param name="kmsType">Type of the KMS Id</param>
        /// <param name="materialsDescription"></param>
        public EncryptionMaterialsV2(string kmsKeyId, KmsType kmsType, Dictionary<string, string> materialsDescription)
            : base(null, null, kmsKeyId, materialsDescription)
        {
            if (materialsDescription == null)
            {
                throw new ArgumentNullException(nameof(materialsDescription));
            }

            if (materialsDescription.ContainsKey(EncryptionUtils.XAmzEncryptionContextCekAlg))
            {
                throw new ArgumentException($"Conflict in reserved KMS Encryption Context key {EncryptionUtils.XAmzEncryptionContextCekAlg}. " +
                                            $"This value is reserved for the S3 Encryption Client and cannot be set by the user.");
            }
                
            materialsDescription[EncryptionUtils.XAmzEncryptionContextCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue;
            KmsType = kmsType;
        }

        /// <summary>
        /// Constructs a new EncryptionMaterials object, storing a KMS Key ID
        /// </summary>
        /// <param name="kmsKeyId">Generic KMS Id</param>
        /// <param name="kmsType">Type of the KMS Id</param>
        public EncryptionMaterialsV2(string kmsKeyId, KmsType kmsType)
            : base(null, null, kmsKeyId, DefaultMaterialsDescription)
        {
            KmsType = kmsType;
        }
    }
}
