namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Defines the content encryption algorithm for S3 encryption operations
    /// The Content Encryption Algorithm determines which algorithm suite the object is encrypted with.
    /// </summary>
    public enum ContentEncryptionAlgorithm
    {
        /// <summary>
        /// AES-GCM without key commitment for content encryption.
        /// This algorithm encrypts object data using AES-GCM but does not cryptographically bind the data encryption key to the ciphertext.                                                                                                                                                                                                                                       
        /// When using Instruction Files, this does not protect against the data key being tampered with and could allow key substitution attacks.                                                                                                                                                                                                                                                                  
        /// This is compatible with all versions of the S3 Encryption Client.
        /// </summary>
        AesGcm,
        
        /// <summary>
        /// AES-GCM with key commitment for content encryption.                                                                                                                                                                                                                                                                        
        /// This algorithm encrypts object data using AES-GCM and cryptographically binds the data encryption key to the ciphertext.
        /// When using Instruction Files, this protects against the data key stored in the instruction file from being tampered with and protects against key substitution attacks.                                                                                                                                                                                                                                      
        /// V4 clients can read and write both while V2/V3 clients can only read objects encrypted with this algorithm.
        /// Ensure all readers have been upgraded to V4 before encrypting with this algorithm.
        /// </summary>
        AesGcmWithCommitment
    }
}