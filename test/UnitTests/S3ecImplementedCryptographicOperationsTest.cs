using System;
using System.Buffers;
using System.Reflection;
using System.Security.Cryptography;
using Amazon.Extensions.S3.Encryption.Util;
using Xunit;
using Xunit.Extensions;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class S3ecImplementedCryptographicOperationsTest
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(128 / 8)]
        [InlineData(256 / 8)]
        [InlineData(512 / 8)]
        [InlineData(28)]
        [InlineData(96)]
        [InlineData(1024)]
        public static void EqualReturnsTrue(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[testSpan.Length];
                rng.GetBytes(bytes);
                bytes.CopyTo(testSpan);
            }

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);

            bool isEqual = S3ecImplementedCryptographicOperations.FixedTimeEquals(testSpan, testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.True(isEqual);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(128 / 8)]
        [InlineData(256 / 8)]
        [InlineData(512 / 8)]
        [InlineData(28)]
        [InlineData(96)]
        [InlineData(1024)]
        public static void UnequalReturnsFalse(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[testSpan.Length];
                rng.GetBytes(bytes);
                bytes.CopyTo(testSpan);
            }

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);
            testSpan[testSpan[0] % testSpan.Length] ^= 0xFF;

            bool isEqual = S3ecImplementedCryptographicOperations.FixedTimeEquals(testSpan, testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.False(isEqual);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(128 / 8)]
        [InlineData(256 / 8)]
        [InlineData(512 / 8)]
        [InlineData(28)]
        [InlineData(96)]
        [InlineData(1024)]
        public static void DifferentLengthsReturnFalse(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[testSpan.Length];
                rng.GetBytes(bytes);
                bytes.CopyTo(testSpan);
            }

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);

            bool isEqualA = S3ecImplementedCryptographicOperations.FixedTimeEquals(testSpan, testSpan2.Slice(0, byteLength - 1));
            bool isEqualB = S3ecImplementedCryptographicOperations.FixedTimeEquals(testSpan.Slice(0, byteLength - 1), testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.False(isEqualA, "value, value missing last byte");
            Assert.False(isEqualB, "value missing last byte, value");
        }

        [Fact]
        public static void HasCorrectMethodImpl()
        {
            Type t = typeof(S3ecImplementedCryptographicOperations);
            MethodInfo mi = t.GetMethod(nameof(S3ecImplementedCryptographicOperations.FixedTimeEquals),
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(mi);
            // This method cannot be optimized, or it loses its fixed time guarantees.
            // It cannot be inlined, or it loses its no-optimization guarantee.
            Assert.Equal(
                MethodImplAttributes.NoInlining | MethodImplAttributes.NoOptimization,
                mi.MethodImplementationFlags);
        }
    }
}