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

using System.Collections.Generic;

namespace AWSSDK.Extensions.S3.Encryption.Utils
{
    internal class ConcurrentDictionary<KeyType, ValueType>
    {
        private readonly object _lock = new object();
        private readonly Dictionary<KeyType, ValueType> _internalDictionary = new Dictionary<KeyType, ValueType>();

        public ValueType this[KeyType key]
        {
            get
            {
                lock (_lock)
                {
                    return _internalDictionary[key];
                }
            }

            set
            {
                lock (_lock)
                {
                    _internalDictionary[key] = value;
                }
            }
        }

        public bool TryGetValue(KeyType key, out ValueType value)
        {
            lock (_lock)
            {
                return _internalDictionary.TryGetValue(key, out value);
            }
        }

        public bool ContainsKey(KeyType key)
        {
            lock (_lock)
            {
                return _internalDictionary.ContainsKey(key);
            }
        }

        public void Add(KeyType key, ValueType value)
        {
            lock (_lock)
            {
                _internalDictionary.Add(key, value);
            }
        }

        public bool Remove(KeyType key)
        {
            lock (_lock)
            {
                return _internalDictionary.Remove(key);
            }
        }
    }
}