namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// SecurityProfile enables a newer client version to downgrade to an older version of content encryption and key wrap schemas
    /// For example, V4AndLegacy enables AmazonS3EncryptionClientV4 to read objects encrypted by AmazonS3EncryptionClient (V1 and V2)
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
        V2AndLegacy,
        
        /// <summary>
        /// Enables AmazonS3EncryptionClientV4 key wrap and content encryption schemas
        /// which are only supported by AmazonS3EncryptionClientV4
        /// </summary>
        V4,

        /// <summary>
        /// Enables AmazonS3EncryptionClient (V1), AmazonS3EncryptionClientV2 and AmazonS3EncryptionClientV4 key wrap and content encryption schemas
        /// With this mode, AmazonS3EncryptionClientV4 can read objects encrypted by AmazonS3EncryptionClient (V1) or AmazonS3EncryptionClientV2  client.
        /// </summary>
        V4AndLegacy
    }
}