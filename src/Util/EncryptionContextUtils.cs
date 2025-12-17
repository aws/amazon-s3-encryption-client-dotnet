using System.Collections.Generic;

namespace Amazon.Extensions.S3.Encryption.Util
{
    public class EncryptionContextUtils
    {
        internal static void AddReservedKeywordToEncryptionContextV2(Dictionary<string, string> EncryptionContext)
        {
            EncryptionContext[EncryptionUtils.XAmzEncryptionContextCekAlg] = EncryptionUtils.XAmzAesGcmCekAlgValue;
        }
        
        internal static void AddReservedKeywordToEncryptionContextV3(Dictionary<string, string> EncryptionContext)
        {
             EncryptionContext[EncryptionUtils.XAmzEncryptionContextCekAlg] =
                 EncryptionUtils.XAmzCekAlgAes256GcmHkdfSha512CommitKey;
        }

    }
}