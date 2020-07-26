using System;
using System.IO;
using System.Linq;
using Amazon.Extensions.S3.Encryption.Model.Internal;
using Amazon.Extensions.S3.Encryption.Util;
using Xunit;
using Xunit.Extensions;
using Xunit.Sdk;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AesCtrDecryptStreamTests
    {
        private static readonly int[] ReadCounts = {1, 15, 16, 17, 32, 1024};
        private const int TagBitsLength = 128;

        [Theory]
        [InlineData("DA2FDB0CED551AEB723D8AC1A267CEF3",
            "",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "A5F5160B7B0B025757ACCDAA",
            "",
            "7AD0758C4FA9B8660AA0687B3E7BD517")]
        [InlineData("4194935CF4524DF93D62FEDBC818D8AC",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "0C5A8F5AF7F6064C0130EE64",
            "3F4CC9A7451717E5E939D294A1362B32C274D06411188DAD76AEE3EE4DA46483EA4C1AF38B9B74D7AD2FD8E310CF82",
            "AD563FD10E1EFA3F26753F46E09DB3A0")]
        [InlineData("AD03EE2FD6048DB7158CEC55D3D760BC",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "",
            "1B813A16DDCB7F08D26E2541",
            "ADD161BE957AE9EC3CEE6600C77FF81D64A80242A510A9D5AD872096C79073B61E8237FAA7D63A3301EA58EC11332C",
            "01944370EC28601ADC989DE05A794AEB")]
        [InlineData("20142E898CD2FD980FBF34DE6BC85C14DA7D57BD28F4AA5CF1728AB64E843142",
            "",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "FB7B4A824E82DAA6C8BC1251",
            "",
            "81C0E42BB195E262CB3B3A74A0DAE1C8")]
        [InlineData("D211F278A44EAB666B1021F4B4F60BA6B74464FA9CB7B134934D7891E1479169",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "6B5CD3705A733C1AD943D58A",
            "4C25ABD66D3A1BCCE794ACAAF4CEFDF6D2552F4A82C50A98CB15B4812FF557ABE564A9CEFF15F32DCF5A5AA7894888",
            "03EDE71EC952E65AE7B4B85CFEC7D304")]
        [InlineData("CFE8BFE61B89AF53D2BECE744D27B78C9E4D74D028CE88ED10A422285B1201C9",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "",
            "5F08EFBFB7BF5BA365D9EB1D",
            "0A7E82F1E5C76C69679671EEAEE455936F2C4FCCD9DDF1FAA27075E2040644938920C5D16C69E4D93375487B9A80D4",
            "04347D0C5B0E0DE89E033D04D0493DCA")]
        public void Decrypt(string key, string expectedPlainText, string aad, string nonce, string cipherText, string tag)
        {
            var keyArray = Utils.HexStringToBytes(key);
            var nonceArray = Utils.HexStringToBytes(nonce);
            var expectedPlainTextArray = Utils.HexStringToBytes(expectedPlainText);

            var cipherTextArray = Utils.HexStringToBytes(cipherText + tag);

            for (var byteOffset = 0; byteOffset < cipherTextArray.Length + 16; byteOffset += 16)
            {
                var start = byteOffset;
                var end = byteOffset + 16;
                var length = end - start;

                var byteRange = new GetObjectResponseByteRange.ByteRange($"bytes {start}-{end}/{cipherTextArray.Length}");
                var rangedCipherText = cipherTextArray.Skip(byteOffset).Take(length).ToArray();

                foreach (var readCount in ReadCounts)
                {
                    // Decryption
                    var decryptedDataStream = DecryptHelper(rangedCipherText, keyArray, nonceArray, byteRange, readCount);
                    var expectedRangedPlainText = Utils.BytesToHexString(expectedPlainTextArray.Skip(byteOffset).Take(length).ToArray());

                    var decryptedPlainTextArray = decryptedDataStream.ToArray();
                    var decryptedPlainText = Utils.BytesToHexString(decryptedPlainTextArray);

                    // Final assert
                    Assert.Equal(expectedRangedPlainText, decryptedPlainText);
                }
            }
        }

        [Theory]
        [InlineData("D211F278A44EAB666B1021F4B4F60BA6B74464FA9CB7B134934D7891E1479169",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
            "6B5CD3705A733C1AD943D58A",
            "4C25ABD66D3A1BCCE794ACAAF4CEFDF6D2552F4A82C50A98CB15B4812FF557ABE564A9CEFF15F32DCF5A5AA7894888",
            "03EDE71EC952E65AE7B4B85CFEC7D304")]
        public void DecryptStartingWithRangeStartInMiddleOfBlock(string key, string expectedPlainText, string aad, string nonce, string cipherText, string tag)
        {
            var keyArray = Utils.HexStringToBytes(key);
            var nonceArray = Utils.HexStringToBytes(nonce);
            var cipherTextArray = Utils.HexStringToBytes(cipherText+tag);

            // Decryption
            var byteRange = new GetObjectResponseByteRange.ByteRange($"bytes {1}-{16}/{cipherTextArray.Length}");
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                DecryptHelper(cipherTextArray, keyArray, nonceArray, byteRange, 16);
            });
            Assert.Equal("Expecting byteOffset to be multiple of 16, but got blockOffset=0, blockSize=16, byteOffset=1", exception.Message);
        }

        public static MemoryStream DecryptHelper(byte[] cipherTextArray, byte[] keyArray, byte[] nonceArray, GetObjectResponseByteRange.ByteRange byteRange, int readCount)
        {
            var decryptedDataStream = new MemoryStream();

            using (var baseStream = new MemoryStream(cipherTextArray))
            using (var stream = new AesCtrDecryptStream(baseStream, keyArray, nonceArray, TagBitsLength, byteRange))
            {
                int readBytes;
                var buffer = new byte[readCount];
                while ((readBytes = stream.Read(buffer, 0, readCount)) > 0)
                {
                    decryptedDataStream.Write(buffer, 0, readBytes);
                }
            }

            return decryptedDataStream;
        }
    }
}