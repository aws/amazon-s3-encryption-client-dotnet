using Amazon.S3.Transfer;
using Amazon.Runtime.Telemetry.Tracing;
using Amazon.Runtime.Telemetry;
using Attributes = Amazon.Runtime.Telemetry.Attributes;
using Amazon.S3;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal static class TelemetryUtilities
    {
        /// <summary>
        /// Creates a new span with the required attributes.
        /// </summary>
        /// <param name="operationName">The name of the operation from which to create the span name.</param>
        /// <param name="initialAttributes">Optional initial set of attributes for the span.</param>
        /// <param name="spanKind">Optional type of span to create.</param>
        /// <param name="parentContext">Optional parent context for the span.</param>
        /// <returns>A <see cref="TraceSpan"/> instance representing the created span.</returns>
        internal static TraceSpan CreateSpan(
            AmazonS3Client client,
            string operationName,
            Attributes initialAttributes = null,
            SpanKind spanKind = SpanKind.INTERNAL,
            SpanContext parentContext = null)
        {
            if (initialAttributes == null)
                initialAttributes = new Attributes();

            initialAttributes.Set(TelemetryConstants.MethodAttributeKey, operationName);

            initialAttributes.Set(TelemetryConstants.SystemAttributeKey, TelemetryConstants.SystemAttributeValue);
            initialAttributes.Set(TelemetryConstants.ServiceAttributeKey, Constants.S3TransferTracerScope);

            var spanName = $"{nameof(TransferUtility)}.{operationName}";

            var tracerProvider = client.Config.TelemetryProvider.TracerProvider;

            var tracer = tracerProvider.GetTracer($"{TelemetryConstants.TelemetryScopePrefix}.{Constants.S3TransferTracerScope}");

            return tracer.CreateSpan(spanName, initialAttributes, spanKind, parentContext);
        }
    }
}
