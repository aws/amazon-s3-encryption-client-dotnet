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
namespace Amazon.Extensions.S3.Encryption.Util
{
    internal class Constants
    {
        internal const string S3CryptoStreamRequestState = "S3-Crypto-Stream";


        internal const string S3TransferTracerScope = "S3.Encryption";
        internal const string SetupEncryptionHandlerSpanName = "EncryptionHandler";
        internal const string SetupDecryptionHandlerSpanName = "DecryptionHandler";
    }
}
