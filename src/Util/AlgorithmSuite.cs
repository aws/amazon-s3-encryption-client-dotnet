using System;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal enum AlgorithmSuiteId : ushort
    {
        AlgAes256CbcIv16NoKdf = 0x0070,
        AlgAes256GcmIv12Tag16NoKdf = 0x0072,
        AlgAes256GcmHkdfSha512CommitKey = 0x0073
    }

    internal enum MessageFormatVersion { V1, V2, V3 }
    internal enum KeyDerivationAlgorithm { Identity, HKDF }
    internal enum KdfHashFunction { None, SHA512 }
    internal enum EncryptionAlgorithm { AES }
    internal enum EncryptionMode { CBC, GCM }

    public class AlgorithmSuite
    {
        internal AlgorithmSuiteId Id { get; }
        
        internal byte[] AlgorithmSuiteIdBytes
        {
            get
            {
                switch (Id)
                {
                    case AlgorithmSuiteId.AlgAes256CbcIv16NoKdf: return new byte[] { 0x00, 0x70 };
                    case AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf: return new byte[] { 0x00, 0x72 };
                    case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey: return new byte[] { 0x00, 0x73 };
                    default: throw new ArgumentException("Unsupported algorithm suite: " + Id);
                }
            }
        }
        internal MessageFormatVersion MessageFormatVersion { get; }
        
        // Algorithm suites may capture a variable-per-algorithm-suite length of data relevant to that algorithm suite’s mode of operation.
        // Currently (11-07-2025), this stores the commit key length
        internal int? AlgorithmSuiteDataLengthInBytes { get; }
        internal int KeyDerivationInputLengthInBits { get; }
        internal KeyDerivationAlgorithm KeyDerivationAlgorithm { get; }
        internal KdfHashFunction KdfHashFunction { get; }
        internal int SaltLengthInBits { get; }
        internal bool KeyCommitment { get; }
        internal EncryptionAlgorithm EncryptionAlgorithm { get; }
        internal EncryptionMode EncryptionMode { get; }
        internal int EncryptionKeyLengthInBits { get; }
        internal int IvLengthInBytes { get; }
        internal int? AuthenticationTagLengthInBytes { get; }
        internal int? KeyDerivationOutputLengthInBits { get; }

        private AlgorithmSuite(AlgorithmSuiteId id, MessageFormatVersion messageFormatVersion, int? algorithmSuiteDataLengthInBytes,
            int keyDerivationInputLengthInBits, KeyDerivationAlgorithm keyDerivationAlgorithm, KdfHashFunction kdfHashFunction, int saltLengthInBits,
            bool keyCommitment, EncryptionAlgorithm encryptionAlgorithm, EncryptionMode encryptionMode, int encryptionKeyLengthInBits,
            int ivLengthInBytes, int? authenticationTagLengthInBytes, int? keyDerivationOutputLengthInBits = null)
        {
            Id = id;
            MessageFormatVersion = messageFormatVersion;
            AlgorithmSuiteDataLengthInBytes = algorithmSuiteDataLengthInBytes;
            KeyDerivationInputLengthInBits = keyDerivationInputLengthInBits;
            KeyDerivationAlgorithm = keyDerivationAlgorithm;
            KdfHashFunction = kdfHashFunction;
            SaltLengthInBits = saltLengthInBits;
            KeyCommitment = keyCommitment;
            EncryptionAlgorithm = encryptionAlgorithm;
            EncryptionMode = encryptionMode;
            EncryptionKeyLengthInBits = encryptionKeyLengthInBits;
            IvLengthInBytes = ivLengthInBytes;
            AuthenticationTagLengthInBytes = authenticationTagLengthInBytes;
            KeyDerivationOutputLengthInBits = keyDerivationOutputLengthInBits;
        }

        internal static readonly AlgorithmSuite AlgAes256CbcIv16NoKdf = new AlgorithmSuite(
            AlgorithmSuiteId.AlgAes256CbcIv16NoKdf, MessageFormatVersion.V1, null, 256, KeyDerivationAlgorithm.Identity, KdfHashFunction.None, 0, false,
            EncryptionAlgorithm.AES, EncryptionMode.CBC, 256, 16, null);

        internal static readonly AlgorithmSuite AlgAes256GcmIv12Tag16NoKdf = new AlgorithmSuite(
            AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf, MessageFormatVersion.V2, null, 256, KeyDerivationAlgorithm.Identity, KdfHashFunction.None, 0, false,
            EncryptionAlgorithm.AES, EncryptionMode.GCM, 256, 12, 16);

        internal static readonly AlgorithmSuite AlgAes256GcmHkdfSha512CommitKey = new AlgorithmSuite(
            AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey, MessageFormatVersion.V3, 28, 256, KeyDerivationAlgorithm.HKDF, KdfHashFunction.SHA512, 224, true,
            EncryptionAlgorithm.AES, EncryptionMode.GCM, 256, 12, 16, 224);

        internal static AlgorithmSuite GetAlgorithmSuit(AlgorithmSuiteId id)
        {
            switch (id)
            {
                case AlgorithmSuiteId.AlgAes256CbcIv16NoKdf: return AlgAes256CbcIv16NoKdf;
                case AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf: return AlgAes256GcmIv12Tag16NoKdf;
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey: return AlgAes256GcmHkdfSha512CommitKey;
                default: throw new ArgumentException("Unsupported algorithm suite: " + id);
            }
        }

        internal static string GetRepresentativeValue(AlgorithmSuite algSuite)
        {
            if (algSuite == null)
                return null;
            switch (algSuite.Id)
            {
                case AlgorithmSuiteId.AlgAes256CbcIv16NoKdf: return EncryptionUtils.XAmzAesCbcPaddingCekAlgValue;
                case AlgorithmSuiteId.AlgAes256GcmIv12Tag16NoKdf: return EncryptionUtils.XAmzAesGcmCekAlgValue;
                case AlgorithmSuiteId.AlgAes256GcmHkdfSha512CommitKey: return EncryptionUtils.XAmzCekAlgAes256GcmHkdfSha512CommitKey;
                default: throw new ArgumentException("Unsupported algorithm suite. Got algorithm suite id: " + algSuite.Id);
            }
        }
    }
}
