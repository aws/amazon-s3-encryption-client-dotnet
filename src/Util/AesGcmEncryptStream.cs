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

using System;
using System.IO;
using Amazon.Runtime.Internal.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;

namespace Amazon.Extensions.S3.Encryption.Util
{
    /// <summary>
    /// A wrapper stream that encrypts the base stream using AES GCM algorithm as it
    /// is being read.
    /// </summary>
    public class AesGcmEncryptStream : EncryptStream
    {
        private readonly long _length;
        private long _position;

        /// <summary>
        /// Gets the length in bytes of the stream.
        /// Length of the string is sum of nonce, cipher text and tag
        /// </summary>
        public override long Length => _length;

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        /// <summary>
        /// Constructor for initializing encryption stream
        /// </summary>
        /// <param name="baseStream">Original data stream</param>
        /// <param name="key">Key to be used for encryption</param>
        /// <param name="nonce">Nonce to be used for encryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="associatedText">Additional associated data</param>
        public AesGcmEncryptStream(Stream baseStream, byte[] key, byte[] nonce, int tagSize, byte[] associatedText = null) 
            : base(new CipherStream(baseStream, AesGcmUtils.CreateCipher(true, key, tagSize, nonce, associatedText), null))
        {
            _length = baseStream.Length + (tagSize / 8);
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
                var readBytes = BaseStream.Read(buffer, offset, count);
                _position += readBytes;
                return readBytes;
            }
            catch (CryptoException cryptoException)
            {
                throw new AmazonCryptoException($"Failed to encrypt: {cryptoException.Message}", cryptoException);
            }
        }

        /// <summary>
        /// Asynchronously reads a sequence of encrypted bytes from the current stream, advances
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
                var readBytes = await BaseStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);;
                _position += readBytes;
                return readBytes;
            }
            catch (CryptoException cryptoException)
            {
                throw new AmazonCryptoException($"Failed to encrypt: {cryptoException.Message}", cryptoException);
            }
        }

        /// <summary>
        /// If set to true the Close and Dispose methods will be a noop. This is necessary in multipart
        /// upload scenarios when we want the SDK to only dispose the stream on the last part.
        /// </summary>
        internal bool DisableDispose { get; set; }

#if NETFRAMEWORK
        /// <inheritdoc/>
        public override void Close()
        {
            if (!DisableDispose)
            {
                base.Close();
            }
        }
#else
        protected override void Dispose(bool disposing)
        {
            if (!DisableDispose)
            {
                base.Dispose(disposing);
            }
        }
#endif
    }
}
