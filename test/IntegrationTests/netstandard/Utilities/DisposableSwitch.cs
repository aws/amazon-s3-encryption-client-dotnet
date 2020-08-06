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

using Amazon.Runtime;
using System;

namespace Amazon.Extensions.S3.Encryption.IntegrationTests.Utilities
{
    public class DisposableSwitch : IDisposable
    {
        private bool CallbacksSet { get; set; }
        private Action EndAction { get; set; }

        public DisposableSwitch(Action onEnd)
            : this(null, onEnd) { }
        public DisposableSwitch(Action onStart, Action onEnd)
        {
            SetCallbacks(onStart, onEnd);
        }

        protected DisposableSwitch()
        { }
        protected void SetCallbacks(Action onStart, Action onEnd)
        {
            if (CallbacksSet)
                throw new InvalidOperationException();

            if (onStart != null)
                onStart();
            EndAction = onEnd;

            CallbacksSet = true;
        }

        public void Dispose()
        {
            if (EndAction != null)
                EndAction();
        }
    }

    public class ServiceResponseCounter : DisposableSwitch
    {
        public int ResponseCount { get; private set; }
        private Predicate<AmazonWebServiceRequest> RequestsToCount { get; set; }
        private AmazonServiceClient Client { get; set; }

        public ServiceResponseCounter(AmazonServiceClient client, Predicate<AmazonWebServiceRequest> requestsToCount = null)
        {
            ResponseCount = 0;
            Client = client;
            RequestsToCount = requestsToCount;

            SetCallbacks(Attach, Detach);
        }

        public void Reset()
        {
            ResponseCount = 0;
        }

        private void Attach()
        {
            Client.AfterResponseEvent += Count;
        }
        private void Detach()
        {
            Client.AfterResponseEvent -= Count;
        }
        private void Count(object sender, ResponseEventArgs e)
        {
            var wsrea = e as WebServiceResponseEventArgs;
            var request = wsrea.Request;

            if (RequestsToCount == null || RequestsToCount(request))
            {
                ResponseCount++;
            }
        }
    }
}
