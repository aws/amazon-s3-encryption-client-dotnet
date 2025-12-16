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
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.ResourceGroupsTaggingAPI;
using Amazon.ResourceGroupsTaggingAPI.Model;
using Tag = Amazon.KeyManagementService.Model.Tag;

namespace AWSSDK.Extensions.S3.Encryption.IntegrationTests.NetStandard.Utilities
{
    public class KmsKeyIdProvider
    {
        private string _kmsId;
        private const string KmsIdTagKey = "Amazon-Extensions-S3-Encryption-Integration-Test";

        public async Task<string> GetKmsIdAsync()
        {
            if (!string.IsNullOrEmpty(_kmsId))
            {
                return _kmsId;
            }

            using (var taggingClient = new AmazonResourceGroupsTaggingAPIClient())
            {
                var getResourcesRequest = new GetResourcesRequest
                {
                    TagFilters = new List<TagFilter>
                    {
                        new TagFilter()
                        {
                            Key = KmsIdTagKey
                        }
                    }
                };
                var resourcesResponse = await taggingClient.GetResourcesAsync(getResourcesRequest);

                if (resourcesResponse.ResourceTagMappingList.Count > 0)
                {
                    var first = resourcesResponse.ResourceTagMappingList.First();
                    _kmsId = first.ResourceARN.Split('/').Last();
                    return _kmsId;
                }
            }

            using (var kmsClient = new AmazonKeyManagementServiceClient())
            {
                var createKeyRequest = new CreateKeyRequest
                {
                    Description = "Key for .NET integration tests.",
                    Origin = OriginType.AWS_KMS,
                    KeyUsage = KeyUsageType.ENCRYPT_DECRYPT,
                    Tags = new List<Tag>
                    {
                        new Tag()
                        {
                            TagKey = KmsIdTagKey,
                            TagValue = string.Empty
                        }
                    }
                };
                var response = await kmsClient.CreateKeyAsync(createKeyRequest);
                _kmsId = response.KeyMetadata.KeyId;
                return _kmsId;
            }
        }
    }
}