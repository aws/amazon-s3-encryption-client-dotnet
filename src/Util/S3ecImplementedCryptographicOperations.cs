using System;
using System.Runtime.CompilerServices;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal static class S3ecImplementedCryptographicOperations
    {
        // FixedTimeEquals function copied from https://github.com/dotnet/runtime/blob/eeb1eae5038a82243d4675c37b6449cac4030207/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptographicOperations.cs#L16-L58
        // And the function access is changed from public to internal.
        // FixedTimeEquals is not available in .NETFRAMEWORK 4.7.2, so this method has to be copied.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }
    }
}