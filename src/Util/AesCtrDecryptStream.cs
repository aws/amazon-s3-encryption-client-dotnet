using System;
using System.IO;
using System.Linq;
using Amazon.Extensions.S3.Encryption.Model.Internal;
using Amazon.Runtime.Internal.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Amazon.Extensions.S3.Encryption.Util
{
    /// <summary>
    /// A wrapper stream that decrypts the base stream using AES CTR algorithm as it
    /// is being read.
    /// </summary>
    public class AesCtrDecryptStream : DecryptStream
    {
        private long _position;

        /// <summary>
        /// Input block size for AES/CTR
        /// </summary>
        private const int BlockSize = 16;

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        /// <summary>
        /// TagSize used for
        /// </summary>
        private readonly int _tagSize;

        /// <summary>
        /// Byte range of the input stream
        /// </summary>
        private readonly GetObjectResponseByteRange.ByteRange _byteRange;

        /// <summary>
        /// Constructor for initializing decryption stream
        /// </summary>
        /// <param name="baseStream">Original data stream</param>
        /// <param name="key">Key to be used for decryption</param>
        /// <param name="nonce">Nonce to be used for decryption</param>
        /// <param name="tagSize">Tag size for the tag appended in the end of the stream</param>
        /// <param name="byteByteRange">Byte range to be used for decryption</param>
        public AesCtrDecryptStream(Stream baseStream, byte[] key, byte[] nonce, int tagSize, GetObjectResponseByteRange.ByteRange byteByteRange)
            : base(new CipherStream(baseStream, CreateCipher(false, key, nonce, byteByteRange), null))
        {
            _tagSize = tagSize;
            _byteRange = byteByteRange;
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
                var bytesToRead = BytesToRead(count);
                if (bytesToRead == 0)
                {
                    return 0;
                }

                var readBytes = BaseStream.Read(buffer, offset, bytesToRead);
                _position += readBytes;
                return readBytes;
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
                var bytesToRead = BytesToRead(count);
                if (bytesToRead == 0)
                {
                    return 0;
                }

                var readBytes = await BaseStream.ReadAsync(buffer, offset, bytesToRead, cancellationToken).ConfigureAwait(false);
                _position += readBytes;
                return readBytes;
            }
            catch (CryptoException cryptoException)
            {
                throw new AmazonCryptoException($"Failed to decrypt: {cryptoException.Message}", cryptoException);
            }
        }
#endif

        /// <summary>
        /// Detects whether the last 16 bytes are included in the range of bytes requested
        /// If true, reduce the byte count to the offset of the tag byte start position
        /// </summary>
        /// <param name="inputCount">Number of bytes requested for read</param>
        /// <returns></returns>
        private int BytesToRead(int inputCount)
        {
            var tagBytesSize = _tagSize / 8;
            var originalPosition = _position + _byteRange.Start;
            if ((originalPosition + inputCount) - (_byteRange.Total - tagBytesSize) > 0)
            {
                return (int)(_byteRange.Total - tagBytesSize - originalPosition);
            }

            return inputCount;
        }

        /// <summary>
        /// Create a buffered cipher to encrypt or decrypt a stream as it is being read
        /// </summary>
        /// <param name="forEncryption">forEncryption if true the cipher is initialised for encryption, if false for decryption</param>
        /// <param name="key">Key to be used for encryption</param>
        /// <param name="nonce">Nonce to be used for encryption</param>
        /// <param name="byteRange"></param>
        /// <returns></returns>
        private static IBufferedCipher CreateCipher(bool forEncryption, byte[] key, byte[] nonce, GetObjectResponseByteRange.ByteRange byteRange)
        {
            var initializationVector = AdjustInitializationVector(nonce, byteRange.Start);

            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(forEncryption, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), initializationVector));
            return cipher;
        }

        /// <summary>
        /// Adjusts AES/GCM nonce to AES/CTR initialization vector
        /// </summary>
        /// <param name="nonce">AES/GCM nonce value</param>
        /// <param name="byteOffset">Zero-based byte offset in the encrypted data</param>
        /// <returns></returns>
        /// <exception cref="UnsupportedOperationException"></exception>
        /// <exception cref="ArgumentException"></exception>
        private static byte[] AdjustInitializationVector(byte[] nonce, long byteOffset)
        {
            if (nonce.Length != EncryptionUtils.DefaultNonceSize)
            {
                throw new NotSupportedException($"Nonce size must be {EncryptionUtils.DefaultNonceSize} bytes which is supported for AES/GCM in CTR mode");
            }

            var blockOffset = byteOffset / BlockSize;
            if (blockOffset * BlockSize != byteOffset)
            {
                throw new ArgumentException($"Expecting byteOffset to be multiple of 16, but got {nameof(blockOffset)}={blockOffset}, " +
                                            $"{nameof(BlockSize)}={BlockSize}, {nameof(byteOffset)}={byteOffset}");
            }

            var j0 = ComputeJ0(nonce);
            var initializationVector = IncrementBlocks(j0, blockOffset);
            return initializationVector;
        }

        /// <summary>
        /// See <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">NIST Special Publication 800-38D.</a> for the definition of J0, the "pre-counter block".
        /// </summary>
        /// <param name="nonce">AES/GCM nonce value</param>
        /// <returns></returns>
        private static byte[] ComputeJ0(byte[] nonce)
        {
            var j0 = new byte[BlockSize];
            Array.Copy(nonce, 0, j0, 0, nonce.Length);
            j0[BlockSize - 1] = 0x01;
            return IncrementBlocks(j0, 1);
        }

        /// <summary>
        /// Increments counter with the given blockDelta
        /// </summary>
        /// <param name="counter">Counter value to be incremented</param>
        /// <param name="blockDelta">Number of blocks that needs to incremented</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        private static byte[] IncrementBlocks(byte[] counter, long blockDelta)
        {
            if (blockDelta == 0)
            {
                return counter;
            }

            if (counter == null || counter.Length != 16)
            {
                throw new ArgumentException(nameof(counter));
            }

            // Allocate 8 bytes for a long
            var byteBuffer = new byte[8];
            // Copy the right-most 32 bits from the counter
            for (var i = 12; i <= 15; i++)
            {
                byteBuffer[i-8] = counter[i];
            }

            var val = BitConverter.ToInt64(byteBuffer.Reverse().ToArray(), 0) + blockDelta;    // increment by delta

            // Get the incremented value (result) as an 8-byte array
            var result = BitConverter.GetBytes(val).Reverse().ToArray();
            // Copy the rightmost 32 bits from the resultant array to the input counter;
            for (var i = 12; i <= 15; i++)
            {
                counter[i] = result[i-8];
            }

            return counter;
        }
    }
}