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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;

namespace Amazon.Runtime.Internal.Util
{
    /// <summary>
    /// A wrapper stream that encrypts the base stream using AES GCM algorithm and caches the contents as it
    /// is being read.
    /// </summary>
    public class AesGcmEncryptCachingStream : AesGcmEncryptStream
    {
        private long _position;

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position
        {
            get => _position;
            set
            {
                if (value < _readBufferStartPosition || value > _position)
                {
                    throw new NotSupportedException($"New position must be >= {_readBufferStartPosition} and <= {_position}");
                }
                _position = value;
            }
        }

        /// <inheritdoc/>
        public override bool CanSeek => true;
        
        /// <summary>
        /// Buffer to cache the read bytes
        /// </summary>
        private readonly List<byte> _readBuffer;

        /// <summary>
        /// Offset since _readBuffer has the read cache
        /// </summary>
        private long _readBufferStartPosition;

        /// <summary>
        /// Constructor for initializing encryption stream
        /// </summary>
        /// <param name="baseStream">Original data stream</param>
        /// <param name="key">Key to be used for encryption</param>
        /// <param name="nonce">Nonce to be used for encryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="associatedText">Additional associated data</param>
        public AesGcmEncryptCachingStream(Stream baseStream,  byte[] key, byte[] nonce, int tagSize, byte[] associatedText = null) 
            : base(baseStream, key, nonce, tagSize, associatedText)
        {
            _readBuffer = new List<byte>();
        }

        /// <summary>
        /// Reads and cache a sequence of encrypted bytes in _readBuffer from the current stream and advances the position
        /// within the stream by the number of bytes read.
        /// If current position lies in between lower bound and upper bound of _readBuffer, reads from the _readBuffer,
        /// else read from the original stream 
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
            var previousPosition = _position;
            CopyFromReadBuffer(buffer, ref offset, ref count);

            var readBytes = base.Read(buffer, offset, count);
            AddReadBytesToReadBuffer(buffer, offset, readBytes);

            return (int)(_position - previousPosition);
        }

#if AWS_ASYNC_API
        /// <summary>
        /// Asynchronously reads and cache a sequence of encrypted bytes in _readBuffer from the current stream, advances
        /// the position within the stream by the number of bytes read, and monitors
        /// cancellation requests.
        /// If current position lies in between lower bound and upper bound of _readBuffer, reads from the _readBuffer,
        /// else read from the original stream 
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
            var previousPosition = _position;
            CopyFromReadBuffer(buffer, ref offset, ref count);

            var readBytes = await base.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            AddReadBytesToReadBuffer(buffer, offset, readBytes);

            return (int)(_position - previousPosition);
        }
#endif
        /// <summary>
        /// Copies bytes to buffer if the current position lies between lower and upper bound of the _readBuffer and
        /// advances the current position.
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes. When this method returns, the buffer contains the specified
        /// byte array with the values between offset and (offset + count - 1) replaced
        /// by the bytes copied from the _readBuffer.
        /// </param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which to begin storing the data read
        /// from the current stream.
        /// </param>
        /// <param name="count">
        /// The maximum number of bytes to be copied from _readBuffer.
        /// </param>
        private void CopyFromReadBuffer(byte[] buffer, ref int offset, ref int count)
        {
            var readBufferOffset = (int)(_position - _readBufferStartPosition);
            var bytesToCopy = Math.Min(_readBuffer.Count - readBufferOffset, count);
            if (bytesToCopy == 0)
            {
                return;
            }

            _readBuffer.CopyTo(readBufferOffset, buffer, offset, bytesToCopy);

            offset += bytesToCopy;
            count -= bytesToCopy;
            _position += bytesToCopy;
        }

        /// <summary>
        /// Add read bytes to _readBuffer and advances the current position
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes containing read bytes</param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which read byte are stored
        /// </param>
        /// <param name="readBytes">
        /// Total number of read bytes
        /// </param>
        private void AddReadBytesToReadBuffer(byte[] buffer, int offset, int readBytes)
        {
            if (readBytes == 0)
            {
                return;
            }

            _readBuffer.AddRange(buffer.Skip(offset).Take(readBytes));
            _position += readBytes;
        }

        /// <summary>
        /// Clear read bytes buffer before current position
        /// </summary>
        public void ClearReadBufferToPosition()
        {
            var bytesToRemove = (int)Math.Min(_position - _readBufferStartPosition, _readBuffer.Count);
            _readBufferStartPosition = _position;
            _readBuffer.RemoveRange(0, bytesToRemove);
        }
    }
}
