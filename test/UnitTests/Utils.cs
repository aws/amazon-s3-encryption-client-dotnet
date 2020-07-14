using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Reflection;

namespace AWSSDK_DotNet35.UnitTests
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
