/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System.Collections.Generic;
using System.IO;
using System.Linq;
using Amazon.Extensions.S3.Encryption.UnitTests;
using Amazon.Extensions.S3.Encryption.Util;
using Xunit;

namespace nAmazon.Extensios.S3.Encryption.UnitTests
{
    public class AesGcmEncryptStreamTests
    {
        private static readonly int[] ReadCounts = {1, 15, 16, 17, 32, 1024};
        private const int TagSize = 16;

        [Fact]
        public void Encrypt()
        {
            var data = new List<List<string>>
            {
                new List<string>
                {
                    "DA2FDB0CED551AEB723D8AC1A267CEF3",
                    "",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "A5F5160B7B0B025757ACCDAA",
                    "",
                    "7AD0758C4FA9B8660AA0687B3E7BD517"
                },
                new List<string>
                {
                    "4194935CF4524DF93D62FEDBC818D8AC",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "0C5A8F5AF7F6064C0130EE64",
                    "3F4CC9A7451717E5E939D294A1362B32C274D06411188DAD76AEE3EE4DA46483EA4C1AF38B9B74D7AD2FD8E310CF82",
                    "AD563FD10E1EFA3F26753F46E09DB3A0"
                },
                new List<string>
                {
                    "AD03EE2FD6048DB7158CEC55D3D760BC",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "",
                    "1B813A16DDCB7F08D26E2541",
                    "ADD161BE957AE9EC3CEE6600C77FF81D64A80242A510A9D5AD872096C79073B61E8237FAA7D63A3301EA58EC11332C",
                    "01944370EC28601ADC989DE05A794AEB"
                },
                new List<string>
                {
                    "20142E898CD2FD980FBF34DE6BC85C14DA7D57BD28F4AA5CF1728AB64E843142",
                    "",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "FB7B4A824E82DAA6C8BC1251",
                    "",
                    "81C0E42BB195E262CB3B3A74A0DAE1C8"
                },
                new List<string>
                {
                    "D211F278A44EAB666B1021F4B4F60BA6B74464FA9CB7B134934D7891E1479169",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "6B5CD3705A733C1AD943D58A",
                    "4C25ABD66D3A1BCCE794ACAAF4CEFDF6D2552F4A82C50A98CB15B4812FF557ABE564A9CEFF15F32DCF5A5AA7894888",
                    "03EDE71EC952E65AE7B4B85CFEC7D304"
                },
                new List<string>
                {
                    "CFE8BFE61B89AF53D2BECE744D27B78C9E4D74D028CE88ED10A422285B1201C9",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "",
                    "5F08EFBFB7BF5BA365D9EB1D",
                    "0A7E82F1E5C76C69679671EEAEE455936F2C4FCCD9DDF1FAA27075E2040644938920C5D16C69E4D93375487B9A80D4",
                    "04347D0C5B0E0DE89E033D04D0493DCA"
                }
            };

            foreach (var line in data)
            {
                var key = line[0];
                var plainText = line[1];
                var aad = line[2];
                var nonce = line[3];
                var expectedCipherText = line[4];
                var expectedTag = line[5];

                var keyArray = Utils.HexStringToBytes(key);
                var plainTextArray = Utils.HexStringToBytes(plainText);
                var nonceArray = Utils.HexStringToBytes(nonce);
                var aadArray = Utils.HexStringToBytes(aad);

                foreach (var readCount in ReadCounts)
                {
                    // Encryption
                    var encryptedDataStream = EncryptHelper(plainTextArray, keyArray, nonceArray, aadArray, readCount);

                    var cipherTextArray = encryptedDataStream.ToArray();

                    // Asserts
                    var tag = Utils.BytesToHexString(cipherTextArray.Skip(cipherTextArray.Length - TagSize).Take(TagSize).ToArray());
                    Assert.Equal(expectedTag, tag);

                    var cipherText =  Utils.BytesToHexString(cipherTextArray.Take(cipherTextArray.Length - TagSize).ToArray());
                    Assert.Equal(expectedCipherText, cipherText);
                }
            }
        }

        public static MemoryStream EncryptHelper(byte[] plainTextArray, byte[] keyArray, byte[] nonceArray, byte[] aadArray, int readCount)
        {
            var encryptedDataStream = new MemoryStream();

            using (var baseStream = new MemoryStream(plainTextArray))
            using (var stream = new AesGcmEncryptStream(baseStream, keyArray, nonceArray, TagSize, aadArray))
            {
                int readBytes;
                var buffer = new byte[readCount];
                while ((readBytes = stream.Read(buffer, 0, readCount)) > 0)
                {
                    encryptedDataStream.Write(buffer, 0, readBytes);
                }
            }

            return encryptedDataStream;
        }
    }
}