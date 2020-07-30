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

using Xunit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public static class AssertExtensions
    {
        public static void ExpectException(Action action, string message = null)
        {
            bool gotException = false;
            try
            {
                action();
            }
            catch (Exception e)
            {
                gotException = true;
                if (!string.IsNullOrEmpty(message))
                    Assert.Equal(message, e.Message);
            }

            Assert.True(gotException, "Failed to get expected exception");
        }

        public static T ExpectException<T>(Action action, string message = null) where T : Exception
        {
            return ExpectException_Helper<T>(action, message);
        }

        private static T ExpectException_Helper<T>(Action action, string message = null) where T : Exception
        {
            var exceptionType = typeof(T);
            bool gotException = false;
            Exception exception = null;
            try
            {
                action();
            }
            catch (Exception e)
            {
                exception = e;
                Assert.Equal(e.GetType(), exceptionType);
                if (!string.IsNullOrEmpty(message))
                    Assert.Equal(message, e.Message);
                gotException = true;
            }

            Assert.True(gotException, "Failed to get expected exception: " + exceptionType.FullName);
            return (T)exception;
        }
    }
}
