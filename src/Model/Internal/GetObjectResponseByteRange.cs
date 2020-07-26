using System;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption.Model.Internal
{
    /// <summary>
    /// Extension class for GetObjectResponse
    /// </summary>
    public static class GetObjectResponseByteRange
    {
        /// <summary>
        /// Container class for range get attributes
        /// </summary>
        public struct ByteRange
        {
            /// <summary>
            /// Start position of blob
            /// </summary>
            public long Start { get; }

            /// <summary>
            /// End position of blob (inclusive)
            /// </summary>
            public long End { get; }

            /// <summary>
            /// Total number of bytes in the original blob stored in S3
            /// </summary>
            public long Total { get; }

            /// <summary>
            /// Constructor to initialize ByteRange from a formatted string
            /// </summary>
            /// <param name="formatted">Formatted string containing start & end position of the blob and total number of bytes in the original blob stored in S3</param>
            /// <exception cref="ArgumentException">Thrown when the string is null or empty</exception>
            public ByteRange(string formatted)
            {
                if (string.IsNullOrEmpty(formatted))
                {
                    throw new ArgumentException(nameof(formatted));
                }

                var rangeAndTotal = formatted.Split('/');
                if (rangeAndTotal.Length != 2)
                {
                    throw new ArgumentException($@"{nameof(formatted)} must be in ""bytes 16-47/48"" format but found {rangeAndTotal}");
                }

                var rangeBytes = rangeAndTotal[0].Split(' ');
                if (rangeBytes.Length != 2)
                {
                    throw new ArgumentException($@"{nameof(rangeBytes)} must be in ""bytes 16-47"" format, but found {rangeBytes}");
                }

                var range = rangeBytes[1].Split('-');
                if (range.Length != 2)
                {
                    throw new ArgumentException($@"{nameof(range)} must be in ""16-47"" format, but found {range}");
                }

                if (!long.TryParse(range[0], out var start))
                {
                    throw new ArgumentException($@"{range[0]} must be of long integral numeric types");
                }
                Start = start;

                if (!long.TryParse(range[1], out var end))
                {
                    throw new ArgumentException($@"{range[1]} must be of long integral numeric types");
                }
                End = end;

                if (!long.TryParse(rangeAndTotal[1], out var total))
                {
                    throw new ArgumentException($"{rangeAndTotal[1]} must be of long integral numeric types");
                }
                Total = total;
            }
        }

        /// <summary>
        /// Checks whether the GetObjectResponse is a range get or response or not.
        /// </summary>
        /// <param name="response">GetObjectResponse whose byte range to be checked</param>
        /// <returns></returns>
        public static bool IsRangeGet(this GetObjectResponse response)
        {
            return !string.IsNullOrEmpty(response.ContentRange);
        }

        /// <summary>
        /// Returns ByteRange of a given GetObjectResponse response
        /// </summary>
        /// <param name="response">GetObjectResponse whose byte range to return</param>
        /// <returns></returns>
        public static ByteRange GetByteRange(this GetObjectResponse response)
        {
            return new ByteRange(response.ContentRange);
        }
    }
}