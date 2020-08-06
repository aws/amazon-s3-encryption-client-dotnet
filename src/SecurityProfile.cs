namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// SecurityProfile enables AmazonS3EncryptionClientV2 downgrading to AmazonS3EncryptionClient (V1) content encryption and key wrap schemas
    /// V2AndLegacy enables AmazonS3EncryptionClientV2 to read objects encrypted by AmazonS3EncryptionClient (V1)
    /// </summary>
    public enum SecurityProfile
    {
        /// <summary>
        /// Enables AmazonS3EncryptionClientV2 key wrap and content encryption schemas
        /// which are only supported by AmazonS3EncryptionClientV2
        /// </summary>
        V2,

        /// <summary>
        /// Enables AmazonS3EncryptionClient (V1) & AmazonS3EncryptionClientV2 key wrap and content encryption schemas
        /// With this mode, AmazonS3EncryptionClientV2 can read objects encrypted by AmazonS3EncryptionClient (V1) client.
        /// </summary>
        V2AndLegacy
    }
}