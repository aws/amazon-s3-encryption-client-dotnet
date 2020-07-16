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

using nAmazon.Extensios.S3.Encryption.UnitTests;
using System;
using System.Collections.Generic;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public class AesGcmStreamTests
    {
        private static readonly int[] ReadCounts = {1, 15, 16, 17, 32, 1024};

        [Fact]
        public void EncryptDecrypt()
        {
            var data = new List<List<string>>
            {
                new List<string>()
                {
                    "DA2FDB0CED551AEB723D8AC1A267CEF3",
                    "",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "A5F5160B7B0B025757ACCDAA"},
                new List<string>
                {
                    "4194935CF4524DF93D62FEDBC818D8AC",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "0C5A8F5AF7F6064C0130EE64"
                },
                new List<string>
                {
                    "AD03EE2FD6048DB7158CEC55D3D760BC",
                    "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                    "",
                    "1B813A16DDCB7F08D26E2541"
                },
                 new List<string>
                 {
                     "20142E898CD2FD980FBF34DE6BC85C14DA7D57BD28F4AA5CF1728AB64E843142",
                     "",
                     "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                     "FB7B4A824E82DAA6C8BC1251"
                 },
                 new List<string>
                 {
                     "D211F278A44EAB666B1021F4B4F60BA6B74464FA9CB7B134934D7891E1479169",
                     "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                     "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                     "6B5CD3705A733C1AD943D58A"
                 },
                 new List<string>
                 {
                     "CFE8BFE61B89AF53D2BECE744D27B78C9E4D74D028CE88ED10A422285B1201C9",
                     "167B5C226177733A782D616D7A2D63656B2D616C675C223A205C224145532F47434D2F4E6F50616464696E675C227D",
                     "",
                     "5F08EFBFB7BF5BA365D9EB1D"
                 }
            };

            foreach (var line in data)
            {
                var key = line[0];
                var plainText = line[1];
                var aad = line[2];
                var nonce = line[3];

                var keyArray = Utils.HexStringToBytes(key);
                var plainTextArray = Utils.HexStringToBytes(plainText);
                var nonceArray = Utils.HexStringToBytes(nonce);
                var aadArray = Utils.HexStringToBytes(aad);

                foreach (var readCount in ReadCounts)
                {
                    // Encryption
                    var encryptedDataStream = AesGcmEncryptStreamTests.EncryptHelper(plainTextArray, keyArray, nonceArray, aadArray, readCount);

                    var cipherTextArray = encryptedDataStream.ToArray();

                    // Decryption
                    var decryptedDataStream = AesGcmDecryptStreamTests.DecryptHelper(cipherTextArray, keyArray, nonceArray, aadArray, readCount);

                    var decryptedPlainTextArray = decryptedDataStream.ToArray();
                    var decryptedPlainText = Utils.BytesToHexString(decryptedPlainTextArray);

                    // Final assert
                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }
    }
}