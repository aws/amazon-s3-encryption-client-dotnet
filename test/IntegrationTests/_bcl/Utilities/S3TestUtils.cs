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
using System.Collections.Generic;
using System.Linq;
using System.Text;


using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Util;
using System.Threading;
using Amazon;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public static class S3TestUtils
    {
        private const int MAX_SPIN_LOOPS = 100;

        public static string CreateBucket(IAmazonS3 s3Client)
        {
            string bucketName = $"{UtilityMethods.SDK_TEST_PREFIX}-{Guid.NewGuid()}";
            s3Client.PutBucket(new PutBucketRequest { BucketName = bucketName });
            return bucketName;
        }

        public static string CreateBucketWithWait(IAmazonS3 s3Client)
        {
            string bucketName = CreateBucket(s3Client);
            WaitForBucket(s3Client, bucketName);
            return bucketName;
        }

        public static void WaitForBucket(IAmazonS3 client, string bucketName)
        {
            WaitForBucket(client, bucketName, 30);
        }

        public static void WaitForBucket(IAmazonS3 client, string bucketName, int maxSeconds)
        {
            var sleeper = UtilityMethods.ListSleeper.Create();
            UtilityMethods.WaitUntilSuccess(() => {
                //Check if a bucket exists by trying to put an object in it
                var key = Guid.NewGuid().ToString() + "_existskey";

                var res = client.PutObject(new PutObjectRequest
                {
                    BucketName = bucketName,
                    Key = key,
                    ContentBody = "exists..."
                });

                try
                {
                    client.Delete(bucketName, key, null);
                }
                catch
                {
                    Console.WriteLine($"Eventual consistency error: failed to delete key {key} from bucket {bucketName}");
                }

                return true;
            });

            //Double check the bucket still exists using the DoesBucketExistV2 method
            var exists = S3TestUtils.WaitForConsistency(() =>
            {
                return AmazonS3Util.DoesS3BucketExistV2(client, bucketName) ? (bool?)true : null;
            });
        }

        public static T WaitForConsistency<T>(Func<T> loadFunction)
        {
            //First try waiting up to 60 seconds.    
            var firstWaitSeconds = 60;
            try
            {
                return UtilityMethods.WaitUntilSuccess(loadFunction, 10, firstWaitSeconds);
            }
            catch
            {
                Console.WriteLine($"Eventual consistency wait: could not resolve eventual consistency after {firstWaitSeconds} seconds. Attempting to resolve...");
            }

            //Spin through request to try to get the expected result. As soon as we get a non null result use it.
            for (var spinCounter = 0; spinCounter < MAX_SPIN_LOOPS; spinCounter++)
            {
                try
                {
                    T result = loadFunction();
                    if (result != null)
                    {
                        if (spinCounter != 0)
                        {
                            //Only log that a wait happened if it didn't do it on the first time.
                            Console.WriteLine($"Eventual consistency wait successful on attempt {spinCounter + 1}.");
                        }

                        return result;
                    }
                }
                catch
                {
                }

                Thread.Sleep(0);
            }

            //If we don't have an ok result then spend the normal wait period to wait for eventual consistency.
            Console.WriteLine($"Eventual consistency wait: could not resolve eventual consistency after {MAX_SPIN_LOOPS}. Waiting normally...");
            var lastWaitSeconds = 240; //4 minute wait.
            return UtilityMethods.WaitUntilSuccess(loadFunction, 5, lastWaitSeconds);
        }
    }
}
