/*******************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 *  this file except in compliance with the License. A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 *  or in the "license" file accompanying this file.
 *  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 *  CONDITIONS OF ANY KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations under the License.
 * *****************************************************************************
 *    __  _    _  ___
 *   (  )( \/\/ )/ __)
 *   /__\ \    / \__ \
 *  (_)(_) \/\/  (___/
 *
 *  AWS SDK for .NET
 *
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Amazon.Runtime.Internal.Util
{
    /// <summary>
    /// Base class for AES GCM encryption and decryption streams containing common operations
    /// </summary>
    public abstract class AesGcmStream : WrapperStream
    {
        protected AesGcmStream(CipherStream baseStream) : base(baseStream)
        {
        }

        /// <summary>
        /// Create a buffered cipher to encrypt or decrypt a stream as it is being read
        /// </summary>
        /// <param name="forEncryption">forEncryption if true the cipher is initialised for encryption, if false for decryption</param>
        /// <param name="key">Key to be used for encryption</param>
        /// <param name="nonce">Nonce to be used for encryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="associatedText">Additional associated data</param>
        /// <returns></returns>
        internal static IBufferedCipher CreateCipher(bool forEncryption, byte[] key, int tagSize, byte[] nonce, byte[] associatedText)
        {
            var aesEngine = new AesEngine();
            var blockCipher = new GcmBlockCipher(aesEngine);
            var aeadBlockCipher = new BufferedAeadBlockCipher(blockCipher);
            var parameters = new AeadParameters(new KeyParameter(key), tagSize * 8, nonce, associatedText);
            aeadBlockCipher.Init(forEncryption, parameters);
            return aeadBlockCipher;
        }
    }
}