﻿/*******************************************************************************
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

using System.IO;
using Amazon.Runtime.Internal.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;

namespace Amazon.Extensions.S3.Encryption.Util
{
    /// <summary>
    /// A wrapper stream that decrypts the base stream using AES GCM algorithm as it
    /// is being read.
    /// </summary>
    public class AesGcmDecryptStream : DecryptStream
    {
        /// <summary>
        /// Constructor for initializing decryption stream
        /// </summary>
        /// <param name="baseStream">Original data stream</param>
        /// <param name="key">Key to be used for decryption</param>
        /// <param name="nonce">Nonce to be used for decryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="associatedText">Additional associated data</param>
        public AesGcmDecryptStream(Stream baseStream, byte[] key, byte[] nonce, int tagSize, byte[] associatedText = null)
            : base(new CipherStream(baseStream, AesGcmUtils.CreateCipher(false, key, tagSize, nonce, associatedText), null))
        {
        }

        /// <summary>
        /// Reads a sequence of encrypted bytes from the current stream and advances the position
        /// within the stream by the number of bytes read.
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes. When this method returns, the buffer contains the specified
        /// byte array with the values between offset and (offset + count - 1) replaced
        /// by the bytes read from the current source.
        /// </param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which to begin storing the data read
        /// from the current stream.
        /// </param>
        /// <param name="count">
        /// The maximum number of bytes to be read from the current stream.
        /// </param>
        /// <returns>
        /// The total number of bytes read into the buffer. This can be less than the
        /// number of bytes requested if that many bytes are not currently available,
        /// or zero (0) if the end of the stream has been reached.
        /// </returns>
        /// <exception cref="AmazonCryptoException">
        /// Underlying crypto exception wrapped in Amazon exception
        /// </exception>
        public override int Read(byte[] buffer, int offset, int count)
        {
            try
            {
                return BaseStream.Read(buffer, offset, count);
            }
            catch (CryptoException cryptoException)
            {
                throw new AmazonCryptoException($"Failed to decrypt: {cryptoException.Message}", cryptoException);
            }
        }

#if AWS_ASYNC_API
        /// <summary>
        /// Asynchronously reads a sequence of decrypted bytes from the current stream, advances
        /// the position within the stream by the number of bytes read, and monitors
        /// cancellation requests.
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes. When this method returns, the buffer contains the specified
        /// byte array with the values between offset and (offset + count - 1) replaced
        /// by the bytes read from the current source.
        /// </param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which to begin storing the data read
        /// from the current stream.
        /// </param>
        /// <param name="count">
        /// The maximum number of bytes to be read from the current stream.
        /// </param>
        /// <param name="cancellationToken">
        /// The token to monitor for cancellation requests. The default value is
        /// System.Threading.CancellationToken.None.
        /// </param>
        /// <returns>
        /// A task that represents the asynchronous read operation. The value of the TResult
        /// parameter contains the total number of bytes read into the buffer. This can be
        /// less than the number of bytes requested if that many bytes are not currently
        /// available, or zero (0) if the end of the stream has been reached.
        /// </returns>
        /// <exception cref="AmazonCryptoException">
        /// Underlying crypto exception wrapped in Amazon exception
        /// </exception>
        public override async System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
        {
            try
            {
                var readBytes = await BaseStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                return readBytes;
            }
            catch (CryptoException cryptoException)
            {
                throw new AmazonCryptoException($"Failed to decrypt: {cryptoException.Message}", cryptoException);
            }
        }
#endif
    }
}