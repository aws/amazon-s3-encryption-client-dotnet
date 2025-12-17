namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// Defines the key commitment policy for S3 encryption operations
    /// Key commitment protects against key substitution attacks by cryptographically binding the encryption key to the ciphertext.
    /// </summary>
    public enum CommitmentPolicy
    {
        /// <summary>
        /// Encrypts objects without key commitment and allows decryption of objects with or without key commitment.
        /// This policy does not protect against key substitution attacks.
        /// Use this policy to maintain backward compatibility during migration from AES/GCM to AES/GCM with key commitment
        /// </summary>
        ForbidEncryptAllowDecrypt,
        
        /// <summary>
        /// Encrypts objects with key commitment (AES-GCM with commitment) and allows decryption of objects with or without key commitment.
        /// This policy protects newly encrypted objects against key substitution attacks while maintaining backward compatibility for decryption.
        /// Use this policy when actively migrating to key commitment.
        /// </summary>
        RequireEncryptAllowDecrypt,
        
        /// <summary>
        /// Encrypts objects with key commitment and only decrypts objects encrypted with key commitment.
        /// This policy fully enforces key commitment and protects against key substitution attacks.
        /// Before using this policy, ensure all objects have been re-encrypted with key commitment.
        /// </summary>
        RequireEncryptRequireDecrypt
    }
}
