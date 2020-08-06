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
using Amazon.Runtime;
using AWSSDK.Extensions.S3.Encryption.IntegrationTests.Utilities;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests
{
    public abstract class TestBase
    {
        public const string CategoryAttribute = "Category";

        static TestBase()
        {
            AWSConfigs.RegionEndpoint = RegionEndpoint.USEast1;
        }

        public TestBase()
        {
        }

        public static TClient CreateClient<TClient>(AWSCredentials credentials = null,
            RegionEndpoint endpoint = null) where TClient : AmazonServiceClient
        {
            endpoint = endpoint ?? AWSConfigs.RegionEndpoint;
            if (credentials != null)
            {
                return (TClient)Activator.CreateInstance(typeof(TClient),
                    new object[] {credentials, endpoint});
            }
            else
            {
                return (TClient)Activator.CreateInstance(typeof(TClient),
                    new object[] {endpoint});
            }
        }
    }

    public abstract class TestBase<T> : TestBase, IDisposable
        where T : AmazonServiceClient, IDisposable
    {
        protected readonly KmsKeyIdProvider _kmsKeyIdProvider;
        private bool _disposed = false;

        private T _client = null;

        public T Client
        {
            get
            {
                if (_client == null)
                {
                    _client = CreateClient<T>(endpoint: ActualEndpoint);
                }

                return _client;
            }
        }


        public static string BaseDirectoryPath { get; set; }

        protected virtual RegionEndpoint AlternateEndpoint
        {
            get { return null; }
        }

        protected RegionEndpoint ActualEndpoint
        {
            get { return (AlternateEndpoint ?? AWSConfigs.RegionEndpoint); }
        }

        static TestBase()
        {
            BaseDirectoryPath = Directory.GetCurrentDirectory();
        }

        public TestBase(KmsKeyIdProvider kmsKeyIdProvider)
        {
            _kmsKeyIdProvider = kmsKeyIdProvider;
        }

        #region IDispose implementation

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                this.Client.Dispose();
                _disposed = true;
            }
        }

        #endregion
    }
}