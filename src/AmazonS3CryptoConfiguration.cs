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
using Amazon.S3;

namespace Amazon.Extensions.S3.Encryption
{
    /// <summary>
    /// AmazonS3CryptoConfiguration allows customers
    /// to set storage mode for encryption credentials
    /// for AmazonS3EncryptionClient
    /// </summary>
    public class AmazonS3CryptoConfiguration: AmazonS3CryptoConfigurationBase
    {
    }
}