﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.Util;

namespace Amazon.Extensions.S3.Encryption.Internal
{
    /// <summary>
    /// Adds the crypto token to the user agent
    /// </summary>
    public class UserAgentHandler : PipelineHandler
    {
        private string _userAgentSuffix;

        /// <summary>
        /// Construct instance of UserAgentHandler.
        /// </summary>
        public UserAgentHandler() : this("S3Crypto")
        {
        }

        /// <summary>
        /// Construct instance of UserAgentHandler with specified user agent suffix.
        /// </summary>
        /// <param name="userAgentSuffix">User agent prefix to be used for the encryption client</param>
        public UserAgentHandler(string userAgentSuffix)
        {
            _userAgentSuffix = userAgentSuffix;
        }

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context which contains both the
        /// requests and response context.</param>
        public override void InvokeSync(IExecutionContext executionContext)
        {
            PreInvoke(executionContext);
            base.InvokeSync(executionContext);
        }
#if AWS_ASYNC_API

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <typeparam name="T">The response type for the current request.</typeparam>
        /// <param name="executionContext">The execution context, it contains the
        /// request and response context.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public override System.Threading.Tasks.Task<T> InvokeAsync<T>(IExecutionContext executionContext)
        {
            PreInvoke(executionContext);
            return base.InvokeAsync<T>(executionContext);                        
        }

#elif AWS_APM_API

        /// <summary>
        /// Calls pre invoke logic before calling the next handler 
        /// in the pipeline.
        /// </summary>
        /// <param name="executionContext">The execution context which contains both the
        /// requests and response context.</param>
        /// <returns>IAsyncResult which represent an async operation.</returns>
        public override IAsyncResult InvokeAsync(IAsyncExecutionContext executionContext)
        {
            PreInvoke(ExecutionContext.CreateFromAsyncContext(executionContext));
            return base.InvokeAsync(executionContext);
        }
#endif

        /// <summary>
        /// Customize the user agent.
        /// </summary>
        /// <param name="executionContext"></param>
        protected virtual void PreInvoke(IExecutionContext executionContext)
        {
            var request = executionContext.RequestContext.Request;
            string currentUserAgent = request.Headers[AWSSDKUtils.UserAgentHeader];
            request.Headers[AWSSDKUtils.UserAgentHeader] = $"{currentUserAgent} {_userAgentSuffix}";
        }
    }
}
