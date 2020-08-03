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
using System.Text;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Encryption Instructions store the encryption credentials
    /// </summary>
    public class EncryptionInstructions
    {
        internal byte[] EnvelopeKey { get; private set; }
        internal byte[] EncryptedEnvelopeKey { get; private set; }
        internal byte[] InitializationVector { get; private set; }
        internal Dictionary<string, string> MaterialsDescription { get; private set; }

        /// <summary>
        /// Algorithm used to encrypt/decrypt content
        /// </summary>
        internal string CekAlgorithm { get; }

        /// <summary>
        /// Algorithm used to encrypt/decrypt envelope key
        /// </summary>
        internal string WrapAlgorithm { get; }

        /// <summary>
        /// Construct an instance EncryptionInstructions.
        /// </summary>
        /// <param name="materialsDescription"></param>
        /// <param name="envelopeKey"></param>
        /// <param name="encryptedKey"></param>
        /// <param name="iv"></param>
        /// <param name="wrapAlgorithm"></param>
        /// <param name="cekAlgorithm"></param>
        public EncryptionInstructions(Dictionary<string, string> materialsDescription, byte[] envelopeKey, byte[] encryptedKey, byte[] iv, string wrapAlgorithm = null,
            string cekAlgorithm = null)
        {
            MaterialsDescription = materialsDescription;
            EnvelopeKey = envelopeKey;
            EncryptedEnvelopeKey = encryptedKey;
            InitializationVector = iv;
            WrapAlgorithm = wrapAlgorithm;
            CekAlgorithm = cekAlgorithm;
        }

        /// <summary>
        /// Construct an instance EncryptionInstructions.
        /// </summary>
        /// <param name="materialsDescription"></param>
        /// <param name="envelopeKey"></param>
        /// <param name="iv"></param>
        public EncryptionInstructions(Dictionary<string, string> materialsDescription, byte[] envelopeKey, byte[] iv) :
            this(materialsDescription, envelopeKey, null, iv)
        {
        }
    }
}
