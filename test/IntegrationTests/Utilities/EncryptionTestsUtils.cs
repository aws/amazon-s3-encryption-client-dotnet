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
using System.IO;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    internal partial class EncryptionTestsUtils
    {
        public const string EncryptionPutObjectFilePrefix = "EncryptionPutObjectFile";
        public const string RangeGetNotSupportedMessage = "Unable to perform range get request: Range get is not supported. " +
                                                          "See https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html";

        public static string GetRandomFilePath(string prefix)
        {
            var random = new Random();
            return Path.Combine(Path.GetTempPath(), $"{prefix}-{random.Next()}.txt");
        }
    }
}