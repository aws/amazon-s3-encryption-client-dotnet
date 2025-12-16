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
using System.Text;
using Amazon.Extensions.S3.Encryption.Util;

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
        /// EncryptionContext to send to AWS KMS. Until V2 message format, EncryptionContext and MaterialsDescription was combined.
        /// From V3 message format, EncryptionContext and MaterialsDescription was separated.
        /// </summary>
        internal Dictionary<string, string> EncryptionContext { get; }

        /// <summary>
        /// AlgorithmSuite used in encryption/decryption of content
        /// </summary>
        internal AlgorithmSuite AlgorithmSuite { get; }

        /// <summary>
        /// Algorithm used to encrypt/decrypt envelope key
        /// </summary>
        internal string WrapAlgorithm { get; }
        
        /// <summary>
        /// Message ID used in encryption and decryption
        /// </summary>
        internal byte[] MessageId { get; }
        
        /// <summary>
        /// Key Commitment of the data key if the algorithm suite supports one 
        /// </summary>
        internal byte[] KeyCommitment { get; }

        /// <summary>
        /// Construct an instance EncryptionInstructions.
        /// </summary>
        /// <param name="materialsDescription"></param>
        /// <param name="envelopeKey"></param>
        /// <param name="encryptedKey"></param>
        /// <param name="iv"></param>
        /// <param name="wrapAlgorithm"></param>
        /// <param name="algorithmSuite"></param>
        public EncryptionInstructions(Dictionary<string, string> materialsDescription, byte[] envelopeKey, byte[] encryptedKey, byte[] iv, string wrapAlgorithm = null,
            AlgorithmSuite algorithmSuite = null)
        {
            MaterialsDescription = materialsDescription;
            EnvelopeKey = envelopeKey;
            EncryptedEnvelopeKey = encryptedKey;
            InitializationVector = iv;
            WrapAlgorithm = wrapAlgorithm;
            AlgorithmSuite = algorithmSuite;
        }
        
        /// <summary>
        /// Construct an instance EncryptionInstructions.
        /// </summary>
        /// <param name="materialsDescription"></param>
        /// <param name="encryptionContext"></param>
        /// <param name="envelopeKey"></param>
        /// <param name="encryptedEnvelopeKey"></param>
        /// <param name="wrapAlgorithm"></param>
        /// <param name="algorithmSuite"></param>
        /// <param name="messageId"></param>
        /// <param name="keyCommitment"></param>
        public EncryptionInstructions(Dictionary<string, string> materialsDescription, Dictionary<string, string> encryptionContext, 
            byte[] envelopeKey, byte[] encryptedEnvelopeKey, string wrapAlgorithm, byte[] messageId, byte[] keyCommitment, AlgorithmSuite algorithmSuite)
        {
            MaterialsDescription = materialsDescription;
            EncryptionContext = encryptionContext;
            EnvelopeKey = envelopeKey;
            EncryptedEnvelopeKey = encryptedEnvelopeKey;
            WrapAlgorithm = wrapAlgorithm;
            AlgorithmSuite = algorithmSuite;
            MessageId = messageId;
            KeyCommitment = keyCommitment;
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
