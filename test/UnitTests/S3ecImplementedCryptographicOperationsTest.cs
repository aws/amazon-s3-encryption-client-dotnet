using System;
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
            byte[] testArray = new byte[byteLength];
#if BCL35
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(testArray);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(testArray);
            }
#endif

            byte[] testArray2 = new byte[byteLength];
            Array.Copy(testArray, testArray2, byteLength);

            bool isEqual = S3ecImplementedCryptographicOperations.FixedTimeEquals(testArray, testArray2);

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
            byte[] testArray = new byte[byteLength];
#if BCL35
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(testArray);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(testArray);
            }
#endif

            byte[] testArray2 = new byte[byteLength];
            Array.Copy(testArray, testArray2, byteLength);
    
            // Modify one byte to make arrays different
            testArray[testArray[0] % testArray.Length] ^= 0xFF;

            bool isEqual = S3ecImplementedCryptographicOperations.FixedTimeEquals(testArray, testArray2);
            
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
            byte[] testArray = new byte[byteLength];
#if BCL35
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(testArray);
#else
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(testArray);
            }
#endif

            byte[] testArray2 = new byte[byteLength];
            Array.Copy(testArray, testArray2, byteLength);
            
            // Create shorter arrays for comparison
            byte[] shorterArray1 = new byte[byteLength - 1];
            byte[] shorterArray2 = new byte[byteLength - 1];
            Array.Copy(testArray, shorterArray1, byteLength - 1);
            Array.Copy(testArray2, shorterArray2, byteLength - 1);

            bool isEqualA = S3ecImplementedCryptographicOperations.FixedTimeEquals(testArray, shorterArray2);
            bool isEqualB = S3ecImplementedCryptographicOperations.FixedTimeEquals(shorterArray1, testArray2);

            Assert.False(isEqualA, "value, value missing last byte");
            Assert.False(isEqualB, "value missing last byte, value");
        }

#if !BCL35
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
#endif
    }
}
