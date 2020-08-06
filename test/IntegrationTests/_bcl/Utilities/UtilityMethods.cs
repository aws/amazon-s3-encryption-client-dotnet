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
using System.Text;
using System.Threading;
using ThirdParty.MD5;
using Xunit;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public static class UtilityMethods
    {
        public const string SDK_TEST_PREFIX = "aws-net-sdk";

        public static void CompareFiles(string file1, string file2)
        {
            byte[] file1MD5 = computeHash(file1);
            byte[] file2MD5 = computeHash(file2);

            Assert.Equal(file1MD5.Length, file2MD5.Length);
            for (int i = 0; i < file1MD5.Length; i++)
            {
                Assert.Equal(file1MD5[i], file2MD5[i]);
            }
        }

        private static byte[] computeHash(string file)
        {
            Stream fileStream = File.OpenRead(file);
            byte[] fileMD5 = new MD5Managed().ComputeHash(fileStream);
            fileStream.Close();
            return fileMD5;
        }

        public static T WaitUntilSuccess<T>(Func<T> loadFunction, int sleepSeconds = 5, int maxWaitSeconds = 300)
        {
            T result = default(T);
            WaitUntil(() =>
            {
                try
                {
                    result = loadFunction();
                    return result != null;
                }
                catch
                {
                    return false;
                }
            }, sleepSeconds, maxWaitSeconds);

            return result;
        }

        public static void WaitUntil(Func<bool> matchFunction, int sleepSeconds = 5, int maxWaitSeconds = 300)
        {
            if (sleepSeconds < 0) throw new ArgumentOutOfRangeException("sleepSeconds");
            WaitUntil(matchFunction, new ListSleeper(sleepSeconds * 1000), maxWaitSeconds);
        }

        public static void WaitUntil(Func<bool> matchFunction, ListSleeper sleeper, int maxWaitSeconds = 300)
        {
            if (maxWaitSeconds < 0) throw new ArgumentOutOfRangeException("maxWaitSeconds");

            var maxTime = TimeSpan.FromSeconds(maxWaitSeconds);
            var endTime = DateTime.Now + maxTime;

            while (DateTime.Now < endTime)
            {
                if (matchFunction())
                    return;
                sleeper.Sleep();
            }

            throw new TimeoutException(
                string.Format("Wait condition was not satisfied for {0} seconds", maxWaitSeconds));
        }

        public static void WriteFile(string path, string contents)
        {
            string fullPath = Path.GetFullPath(path);
            new DirectoryInfo(Path.GetDirectoryName(fullPath)).Create();
            File.WriteAllText(fullPath, contents);
        }

        public static void GenerateFile(string path, long size)
        {
            string contents = GenerateTestContents(size);
            WriteFile(path, contents);
        }

        public static string GenerateTestContents(long size)
        {
            StringBuilder sb = new StringBuilder();
            for (long i = 0; i < size; i++)
            {
                char c = (char)('a' + (i % 26));
                sb.Append(c);
            }

            string contents = sb.ToString();
            return contents;
        }


        public static string GenerateName(string name)
        {
            return name + Guid.NewGuid();
        }

        public class ListSleeper
        {
            private int attempt;
            private int[] millisecondsList;

            public ListSleeper(params int[] millisecondsList)
            {
                if (millisecondsList.Length < 1)
                    throw new ArgumentException("There must be at least one sleep period in millisecondsList.");

                attempt = 0;
                this.millisecondsList = millisecondsList;
            }

            public void Sleep()
            {
                // if there are more attempts than array elements just keep using the last one
                var index = Math.Min(attempt, millisecondsList.Length - 1);
                Thread.Sleep(millisecondsList[index]);
                attempt++;
            }

            /// <summary>
            /// Create a new exponential growth sleeper. The following sleeper will be created:
            /// ListSleeper(500, 1000, 2000, 5000)
            /// </summary>
            /// <returns>A new ListSleeper with exponential growth</returns>
            public static ListSleeper Create()
            {
                return new ListSleeper(500, 1000, 2000, 5000);
            }
        }
    }
}