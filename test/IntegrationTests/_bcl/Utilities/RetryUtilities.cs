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

using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public static class RetryUtilities
    {
        // Flag to force failing of a first request, but passing of retry requests
        public static bool FailOriginalRequests = false;
        public static bool TestClockSkewCorrection = false;
        public static bool SetIncorrectClockOffsetFuture = false;


        #region Retry testing

        public static void ForceConfigureClient(AmazonServiceClient client)
        {
            RetryHttpRequestFactory.AddToClient(client);
        }

        private class RetryHttpRequestFactory : IHttpRequestFactory<Stream>
        {
            public IHttpRequest<Stream> CreateHttpRequest(Uri requestUri)
            {
                var request = new RetryHttpRequest(requestUri);
                return request;
            }
            public void Dispose()
            {
            }

            public static void AddToClient(AmazonServiceClient client)
            {
                var pipeline = client
                    .GetType()
                    .GetProperty("RuntimePipeline", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                    .GetValue(client, null)
                    as RuntimePipeline;

                var requestFactory = new RetryHttpRequestFactory();
                var httpHandler = new HttpHandler<Stream>(requestFactory, client);
                pipeline.ReplaceHandler<HttpHandler<Stream>>(httpHandler);
            }
        }

        private class RetryHttpRequest : HttpRequest
        {
            public RetryHttpRequest(Uri requestUri)
                : base(requestUri)
            {
                IsRetry = false;
            }

            public bool IsRetry { get; private set; }
            public bool IsRewindable { get; private set; }

            public override Amazon.Runtime.Internal.Transform.IWebResponseData GetResponse()
            {
                if (IsRetry || !IsRewindable)
                    return base.GetResponse();
                else
                {
                    base.Abort();
                    throw new WebException("Newp!", null, WebExceptionStatus.ConnectionClosed, null);
                }
            }

#if BCL45
            public override System.Threading.Tasks.Task<IWebResponseData> GetResponseAsync(System.Threading.CancellationToken cancellationToken)
            {
                if (IsRetry || !IsRewindable)
                    return base.GetResponseAsync(cancellationToken);
                else
                {
                    base.Abort();
                    throw new WebException("Newp!", null, WebExceptionStatus.ConnectionClosed, null);
                }
            }

#endif
            

            public override void ConfigureRequest(IRequestContext requestContext)
            {
                base.ConfigureRequest(requestContext);

                IsRetry = requestContext.Retries > 0;
                IsRewindable = requestContext.Request.IsRequestStreamRewindable();
            }
        }

        #endregion
    }
}
