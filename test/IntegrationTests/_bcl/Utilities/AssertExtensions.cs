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
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.IO;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public static class AssertExtensions
    {
        public static Exception ExpectException(Action action, Type exceptionType, String expectedMessage)
        {
            Action<string> validateMessage = expectedMessage == null ? (Action<string>)null :
                (message) =>
                {
                    Assert.Equal(expectedMessage, message);
                };
            return ExpectException(action, exceptionType, validateMessage);
        }

        public static Exception ExpectException(Action action, Type exceptionType, Regex messageRegex)
        {
            Action<string> validateMessage = messageRegex == null ? (Action<string>)null :
                (message) =>
                {
                    Assert.True(messageRegex.IsMatch(message),
                        string.Format("Expected exception message <{0}> to match regular expression <{1}>", message, messageRegex));
                };
            return ExpectException(action, exceptionType, validateMessage);
        }

        public static Exception ExpectException(Action action, Type exceptionType, Action<string> validateMessage)
        {
            bool gotException = false;
            Exception exception = null;
            try
            {
                action();
            }
            catch (Exception e)
            {
                exception = e;

                if (exceptionType != null)
                {
                    Assert.True(exceptionType == e.GetType(), e.ToString());
                }

                if (validateMessage != null)
                {
                    validateMessage(e.Message);
                }
                gotException = true;
            }

            string message = (exceptionType == null) ?
                "Failed to get an exception." :
                String.Format("Failed to get expected exception: {0}", exceptionType.FullName);

            Assert.True(gotException, message);

            return exception;
        }
    }
}
