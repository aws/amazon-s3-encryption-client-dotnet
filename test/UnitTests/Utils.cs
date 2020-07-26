﻿/*
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

using System;

namespace Amazon.Extensions.S3.Encryption.UnitTests
{
    public static class Utils
    {
        public static byte[] HexStringToBytes(string hexString)  
        {
            var stringIndex = 0;
            var byteIndex = 0;
            var bytes = new byte[hexString.Length / 2];
            while (hexString.Length > stringIndex + 1)  
            {  
                long lngDecimal = Convert.ToInt32(hexString.Substring(stringIndex, 2), 16);  
                bytes[byteIndex] = Convert.ToByte(lngDecimal);  
                stringIndex += 2;  
                byteIndex++;  
            }
            return bytes;  
        }  

        public static string BytesToHexString(byte[] bytes)  
        {
            var hexString = "";  
            for (var index = 0; index <= bytes.GetUpperBound(0); index++)  
            {  
                var number = int.Parse(bytes[index].ToString());  
                hexString += number.ToString("X").PadLeft(2, '0');  
            }
            return hexString;  
        }
    }
}
