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
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Amazon.Runtime.Internal.Util
{
    /// <summary>
    /// Base class for AES GCM encryption and decryption streams containing common operations
    /// </summary>
    public abstract class AesGcmStream : Stream
    {
        /// <summary>
        /// Base stream.
        /// </summary>
        protected CipherStream BaseStream { get; }
        
        /// <summary>
        /// Initializes WrapperStream with a base stream.
        /// </summary>
        /// <param name="baseStream">Base stream used for streaming operations</param>
        protected AesGcmStream(CipherStream baseStream)
        {
            BaseStream = baseStream;
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

      #region Stream overrides

        /// <summary>
        /// Gets a value indicating whether the current stream supports reading.
        /// True if the stream supports reading; otherwise, false.
        /// </summary>
        public override bool CanRead => BaseStream.CanRead;

        /// <summary>
        /// Gets a value indicating whether the current stream supports seeking.
        /// True if the stream supports seeking; otherwise, false.
        /// </summary>
        public override bool CanSeek => BaseStream.CanSeek;

        /// <summary>
        /// Gets a value indicating whether the current stream supports writing.
        /// True if the stream supports writing; otherwise, false.
        /// </summary>
        public override bool CanWrite => BaseStream.CanWrite;

        /// <summary>
        /// Closes the current stream and releases any resources (such as sockets and
        /// file handles) associated with the current stream.
        /// </summary>
#if !PCL && !NETSTANDARD
        public override void Close()
        {
            BaseStream.Close();
        }
#else
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            BaseStream.Dispose();
        }
#endif

        /// <summary>
        /// Gets the length in bytes of the stream.
        /// </summary>
        public override long Length => BaseStream.Length;

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position
        {
            get => BaseStream.Position;
            set => BaseStream.Position = value;
        }

        /// <summary>
        /// Gets or sets a value, in milliseconds, that determines how long the stream
        /// will attempt to read before timing out.
        /// </summary>
        public override int ReadTimeout
        {
            get => BaseStream.ReadTimeout;
            set => BaseStream.ReadTimeout = value;
        }

        /// <summary>
        /// Gets or sets a value, in milliseconds, that determines how long the stream
        /// will attempt to write before timing out.
        /// </summary>
        public override int WriteTimeout
        {
            get => BaseStream.WriteTimeout;
            set => BaseStream.WriteTimeout = value;
        }

        /// <summary>
        /// Clears all buffers for this stream and causes any buffered data to be written
        /// to the underlying device.
        /// </summary>
        public override void Flush()
        {
            BaseStream.Flush();
        }

        /// <summary>
        /// Reads a sequence of bytes from the current stream and advances the position
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
        public override int Read(byte[] buffer, int offset, int count)
        {
            return BaseStream.Read(buffer, offset, count);
        }

        /// <summary>
        /// Sets the position within the current stream.
        /// </summary>
        /// <param name="offset">A byte offset relative to the origin parameter.</param>
        /// <param name="origin">
        /// A value of type System.IO.SeekOrigin indicating the reference point used
        /// to obtain the new position.</param>
        /// <returns>The new position within the current stream.</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            return BaseStream.Seek(offset, origin);
        }

        /// <summary>
        /// Sets the length of the current stream.
        /// </summary>
        /// <param name="value">The desired length of the current stream in bytes.</param>
        public override void SetLength(long value)
        {
            BaseStream.SetLength(value);
        }

        /// <summary>
        /// Writes a sequence of bytes to the current stream and advances the current
        /// position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes. This method copies count bytes from buffer to the current stream.
        /// </param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which to begin copying bytes to the
        /// current stream.
        /// </param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            BaseStream.Write(buffer, offset, count);
        }

#if AWS_ASYNC_API
        /// <summary>
        /// Asynchronously clears all buffers for this stream and causes any buffered data
        /// to be written to the underlying device.
        /// </summary>
        /// <param name="cancellationToken">
        /// The token to monitor for cancellation requests. The default value is
        /// System.Threading.CancellationToken.None.
        /// </param>
        /// <returns>
        /// A task that represents the asynchronous flush operation.
        /// </returns>
        public override async System.Threading.Tasks.Task FlushAsync(System.Threading.CancellationToken cancellationToken)
        {
            await BaseStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Asynchronously reads a sequence of bytes from the current stream, advances
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
        public override async System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
        {
            return await BaseStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Asynchronously writes a sequence of bytes to the current stream and advances the
        /// current position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer">
        /// An array of bytes. This method copies count bytes from buffer to the current stream.
        /// </param>
        /// <param name="offset">
        /// The zero-based byte offset in buffer at which to begin copying bytes to the
        /// current stream.
        /// </param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        /// <param name="cancellationToken">
        /// The token to monitor for cancellation requests. The default value is
        /// System.Threading.CancellationToken.None.
        /// </param>
        /// <returns>A task that represents the asynchronous write operation.</returns>
        public override async System.Threading.Tasks.Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken)
        {
            await BaseStream.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }
#endif

#endregion
    }
}