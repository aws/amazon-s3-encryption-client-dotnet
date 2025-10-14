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

using System;
using System.Reflection;
using Amazon.Runtime;
using Moq;

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

        // Reflection is used to test inaccessible methods
        public static object RunInstanceMethod(Type type, string strMethod, object objInstance, object[] objParams)
        {
            BindingFlags flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            return RunMethod(type, strMethod, objInstance, objParams, flags);
        }

        private static object RunMethod(Type type, string strMethod, object objInstance, object[] objParams, BindingFlags flags)
        {
            MethodInfo methodInfo;
            try
            {
                methodInfo = type.GetMethod(strMethod, flags);
                if (methodInfo == null)
                {
                    throw new ArgumentException("There is no method '" + strMethod + "' for type '" + type.ToString() + "'.");
                }

                object objReturn = methodInfo.Invoke(objInstance, objParams);
                return objReturn;
            }
            catch (Exception e)
            {
                throw e.InnerException;
            }
        }
        
        public static Mock<IExecutionContext> CreateMockExecutionContext(AmazonWebServiceRequest request)
        {
            var mockRequestContext = new Mock<IRequestContext>();
            mockRequestContext.Setup(x => x.OriginalRequest).Returns(request);
            
            var mockExecutionContext = new Mock<IExecutionContext>();
            mockExecutionContext.Setup(x => x.RequestContext).Returns(mockRequestContext.Object);
            
            return mockExecutionContext;
        }
    }
}
