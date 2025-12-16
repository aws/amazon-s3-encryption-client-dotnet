namespace Amazon.Extensions.S3.Encryption.Util
{
    internal class GenericUtils
    {
        internal static int ConvertBitToByte(int bitLength)
        {
            return bitLength / 8;
        }
        
        internal static int ConvertByteToBit(int bitLength)
        {
            return bitLength * 8;
        }
    }
}
