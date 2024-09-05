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
using System.Reflection;
using Amazon.Extensions.S3.Encryption.Internal;
using Amazon.Runtime;
using Amazon.Runtime.Internal;
using Amazon.S3.Model;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// This class extends the AmazonS3Client and implements IAmazonS3Encryption
    /// Provides client side encryption when reading or writing S3 objects.
    /// Supported content ciphers:
    ///	AES/GCM - Encryption and decryption (Encrypted block size can be bigger than the input block size)
    ///	AES/CBC - Decryption only
    /// </summary>
    public partial class AmazonS3EncryptionClientV2 : AmazonS3EncryptionClientBase
    {
        private static readonly string _assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? string.Empty;
        private static readonly string _userAgentString = $"lib/amazon-extensions-s3-encryption#{_assemblyVersion} ft/S3CryptoV2";

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(AWSCredentials credentials, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(credentials, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials) 
            : base(awsAccessKeyId, awsSecretAccessKey, config, materials)
        {
        }

        ///<inheritdoc/>
        public AmazonS3EncryptionClientV2(string awsAccessKeyId, string awsSecretAccessKey, string awsSessionToken, AmazonS3CryptoConfigurationV2 config, EncryptionMaterialsV2 materials)
            : base(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, config, materials)
        {
        }
        
        ///<inheritdoc/>
        protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
        {
            base.CustomizeRuntimePipeline(pipeline);

            pipeline.AddHandlerBefore<Amazon.Runtime.Internal.Marshaller>(new SetupEncryptionHandlerV2(this));
            pipeline.AddHandlerAfter<Amazon.Runtime.Internal.Marshaller>(new UserAgentHandler(_userAgentString));
            pipeline.AddHandlerBefore<Amazon.S3.Internal.AmazonS3ResponseHandler>(new SetupDecryptionHandlerV2(this));
        }

        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="request">Container for the necessary parameters to execute the GetObject service method.</param>
        /// <param name="cancellationToken">
        ///     A cancellation token that can be used by other objects or threads to receive notice of cancellation.
        /// </param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override System.Threading.Tasks.Task<GetObjectResponse> GetObjectAsync(GetObjectRequest request,
            System.Threading.CancellationToken cancellationToken = new  System.Threading.CancellationToken())
        {
            return base.GetObjectAsync(request, cancellationToken);
        }

        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="bucketName">The bucket name containing the object.  When using this API with an access point, you must direct requests to the access point hostname. The access point hostname takes the form <i>AccessPointName</i>-<i>AccountId</i>.s3-accesspoint.<i>Region</i>.amazonaws.com. When using this operation using an access point through the AWS SDKs, you provide the access point ARN in place of the bucket name. For more information about access point ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-access-points.html">Using Access Points</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</param>
        /// <param name="key">Key of the object to get.</param>
        /// <param name="cancellationToken">
        ///     A cancellation token that can be used by other objects or threads to receive notice of cancellation.
        /// </param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override System.Threading.Tasks.Task<GetObjectResponse> GetObjectAsync(string bucketName, string key,
            System.Threading.CancellationToken cancellationToken = new  System.Threading.CancellationToken())
        {
            return base.GetObjectAsync(bucketName, key, cancellationToken);
        }

        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="bucketName">The bucket name containing the object.  When using this API with an access point, you must direct requests to the access point hostname. The access point hostname takes the form <i>AccessPointName</i>-<i>AccountId</i>.s3-accesspoint.<i>Region</i>.amazonaws.com. When using this operation using an access point through the AWS SDKs, you provide the access point ARN in place of the bucket name. For more information about access point ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-access-points.html">Using Access Points</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</param>
        /// <param name="key">Key of the object to get.</param>
        /// <param name="versionId">VersionId used to reference a specific version of the object.</param>
        /// <param name="cancellationToken">
        ///     A cancellation token that can be used by other objects or threads to receive notice of cancellation.
        /// </param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override System.Threading.Tasks.Task<GetObjectResponse> GetObjectAsync(string bucketName, string key, string versionId,
            System.Threading.CancellationToken cancellationToken = new  System.Threading.CancellationToken())
        {
            return base.GetObjectAsync(bucketName, key, versionId, cancellationToken);
        }

#if NETFRAMEWORK
        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="request">Container for the necessary parameters to execute the GetObject service method.</param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override GetObjectResponse GetObject(GetObjectRequest request)
        {
            return base.GetObject(request);
        }

        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="bucketName">The bucket name containing the object.  When using this API with an access point, you must direct requests to the access point hostname. The access point hostname takes the form <i>AccessPointName</i>-<i>AccountId</i>.s3-accesspoint.<i>Region</i>.amazonaws.com. When using this operation using an access point through the AWS SDKs, you provide the access point ARN in place of the bucket name. For more information about access point ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-access-points.html">Using Access Points</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</param>
        /// <param name="key">Key of the object to get.</param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override GetObjectResponse GetObject(string bucketName, string key)
        {
            return base.GetObject(bucketName, key);
        }

        /// <summary>
        /// Retrieves objects from Amazon S3. To use <c>GET</c>, you must have <c>READ</c>
        /// access to the object. If you grant <c>READ</c> access to the anonymous user,
        /// you can return the object without using an authorization header.
        ///
        ///
        /// <para>
        /// An Amazon S3 bucket has no directory hierarchy such as you would find in a typical
        /// computer file system. You can, however, create a logical hierarchy by using object
        /// key names that imply a folder structure. For example, instead of naming an object
        /// <c>sample.jpg</c>, you can name it <c>photos/2006/February/sample.jpg</c>.
        /// </para>
        ///
        /// <para>
        /// To get an object from such a logical hierarchy, specify the full key name for the
        /// object in the <c>GET</c> operation. For a virtual hosted-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c>, specify the resource
        /// as <c>/photos/2006/February/sample.jpg</c>. For a path-style request example,
        /// if you have the object <c>photos/2006/February/sample.jpg</c> in the bucket
        /// named <c>examplebucket</c>, specify the resource as <c>/examplebucket/photos/2006/February/sample.jpg</c>.
        /// For more information about request types, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html#VirtualHostingSpecifyBucket">HTTP
        /// Host Header Bucket Specification</a>.
        /// </para>
        ///
        /// <para>
        /// To distribute large files to many people, you can save bandwidth costs by using BitTorrent.
        /// For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/S3Torrent.html">Amazon
        /// S3 Torrent</a>. For more information about returning the ACL of an object, see <a>GetObjectAcl</a>.
        /// </para>
        ///
        /// <para>
        /// If the object you are retrieving is stored in the GLACIER or DEEP_ARCHIVE storage
        /// classes, before you can retrieve the object you must first restore a copy using .
        /// Otherwise, this operation returns an <c>InvalidObjectStateError</c> error. For
        /// information about restoring archived objects, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/restoring-objects.html">Restoring
        /// Archived Objects</a>.
        /// </para>
        ///
        /// <para>
        /// Encryption request headers, like <c>x-amz-server-side-encryption</c>, should
        /// not be sent for GET requests if your object uses server-side encryption with CMKs
        /// stored in AWS KMS (SSE-KMS) or server-side encryption with Amazon S3–managed encryption
        /// keys (SSE-S3). If your object does use these types of keys, you’ll get an HTTP 400
        /// BadRequest error.
        /// </para>
        ///
        /// <para>
        /// If you encrypt an object by using server-side encryption with customer-provided encryption
        /// keys (SSE-C) when you store the object in Amazon S3, then when you GET the object,
        /// you must use the following headers:
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-algorithm
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key
        /// </para>
        ///  </li> <li>
        /// <para>
        /// x-amz-server-side​-encryption​-customer-key-MD5
        /// </para>
        ///  </li> </ul>
        /// <para>
        /// For more information about SSE-C, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html">Server-Side
        /// Encryption (Using Customer-Provided Encryption Keys)</a>.
        /// </para>
        ///
        /// <para>
        /// Assuming you have permission to read object tags (permission for the <c>s3:GetObjectVersionTagging</c>
        /// action), the response also returns the <c>x-amz-tagging-count</c> header that
        /// provides the count of number of tags associated with the object. You can use <a>GetObjectTagging</a>
        /// to retrieve the tag set associated with an object.
        /// </para>
        ///
        /// <para>
        ///  <b>Permissions</b>
        /// </para>
        ///
        /// <para>
        /// You need the <c>s3:GetObject</c> permission for this operation. For more information,
        /// see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html">Specifying
        /// Permissions in a Policy</a>. If the object you request does not exist, the error Amazon
        /// S3 returns depends on whether you also have the <c>s3:ListBucket</c> permission.
        /// </para>
        ///  <ul> <li>
        /// <para>
        /// If you have the <c>s3:ListBucket</c> permission on the bucket, Amazon S3 will
        /// return an HTTP status code 404 ("no such key") error.
        /// </para>
        ///  </li> <li>
        /// <para>
        /// If you don’t have the <c>s3:ListBucket</c> permission, Amazon S3 will return
        /// an HTTP status code 403 ("access denied") error.
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Versioning</b>
        /// </para>
        ///
        /// <para>
        /// By default, the GET operation returns the current version of an object. To return
        /// a different version, use the <c>versionId</c> subresource.
        /// </para>
        ///  <note>
        /// <para>
        /// If the current version of the object is a delete marker, Amazon S3 behaves as if the
        /// object was deleted and includes <c>x-amz-delete-marker: true</c> in the response.
        /// </para>
        ///  </note>
        /// <para>
        /// For more information about versioning, see <a>PutBucketVersioning</a>.
        /// </para>
        ///
        /// <para>
        ///  <b>Overriding Response Header Values</b>
        /// </para>
        ///
        /// <para>
        /// There are times when you want to override certain response header values in a GET
        /// response. For example, you might override the Content-Disposition response header
        /// value in your GET request.
        /// </para>
        ///
        /// <para>
        /// You can override values for a set of response headers using the following query parameters.
        /// These response header values are sent only on a successful request, that is, when
        /// status code 200 OK is returned. The set of headers you can override using these parameters
        /// is a subset of the headers that Amazon S3 accepts when you create an object. The response
        /// headers that you can override for the GET response are <c>Content-Type</c>,
        /// <c>Content-Language</c>, <c>Expires</c>, <c>Cache-Control</c>, <c>Content-Disposition</c>,
        /// and <c>Content-Encoding</c>. To override these header values in the GET response,
        /// you use the following request parameters.
        /// </para>
        ///  <note>
        /// <para>
        /// You must sign the request, either using an Authorization header or a presigned URL,
        /// when using these parameters. They cannot be used with an unsigned (anonymous) request.
        /// </para>
        ///  </note> <ul> <li>
        /// <para>
        ///  <c>response-content-type</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-language</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-expires</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-cache-control</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-disposition</c>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <c>response-content-encoding</c>
        /// </para>
        ///  </li> </ul>
        /// <para>
        ///  <b>Additional Considerations about Request Headers</b>
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-Match</c> and <c>If-Unmodified-Since</c> headers
        /// are present in the request as follows: <c>If-Match</c> condition evaluates to
        /// <c>true</c>, and; <c>If-Unmodified-Since</c> condition evaluates to <c>false</c>;
        /// then, S3 returns 200 OK and the data requested.
        /// </para>
        ///
        /// <para>
        /// If both of the <c>If-None-Match</c> and <c>If-Modified-Since</c> headers
        /// are present in the request as follows:<c> If-None-Match</c> condition evaluates
        /// to <c>false</c>, and; <c>If-Modified-Since</c> condition evaluates to
        /// <c>true</c>; then, S3 returns 304 Not Modified response code.
        /// </para>
        ///
        /// <para>
        /// For more information about conditional requests, see <a href="https://tools.ietf.org/html/rfc7232">RFC
        /// 7232</a>.
        /// </para>
        ///
        /// <para>
        /// The following operations are related to <c>GetObject</c>:
        /// </para>
        ///  <ul> <li>
        /// <para>
        ///  <a>ListBuckets</a>
        /// </para>
        ///  </li> <li>
        /// <para>
        ///  <a>GetObjectAcl</a>
        /// </para>
        ///  </li> </ul>
        /// </summary>
        /// <remarks>
        /// When decrypting with AES-GCM, read the entire object to the end before you start using the decrypted data.
        /// This is to verify that the object has not been modified since it was encrypted.
        /// </remarks>
        /// <param name="bucketName">The bucket name containing the object.  When using this API with an access point, you must direct requests to the access point hostname. The access point hostname takes the form <i>AccessPointName</i>-<i>AccountId</i>.s3-accesspoint.<i>Region</i>.amazonaws.com. When using this operation using an access point through the AWS SDKs, you provide the access point ARN in place of the bucket name. For more information about access point ARNs, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/using-access-points.html">Using Access Points</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</param>
        /// <param name="key">Key of the object to get.</param>
        /// <param name="versionId">VersionId used to reference a specific version of the object.</param>
        /// <returns>The response from the GetObject service method, as returned by S3.</returns>
        /// <seealso href="http://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/GetObject">REST API Reference for GetObject Operation</seealso>
        public override GetObjectResponse GetObject(string bucketName, string key, string versionId)
        {
            return base.GetObject(bucketName, key, versionId);
        }
#endif
    }
}
