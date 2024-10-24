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
using System.IO;
using System.Text;
using System.Text.Json;

namespace Amazon.Extensions.S3.Encryption.Util
{
    internal static class JsonUtils
    {

        internal static string ToJson(Dictionary<string, string> keyValuePairs)
        {
            var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var kvp in keyValuePairs)
                {
                    writer.WriteString(kvp.Key, kvp.Value);
                }
                writer.WriteEndObject();
            }

            stream.Position = 0;
            return new StreamReader(stream).ReadToEnd();
        }

        internal static Dictionary<string,string> ToDictionary(string json)
        {
            var dictionary = new Dictionary<string,string>();
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(bytes));

            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
                throw new InvalidDataException("Key value pair JSON must start with an object.");

            // Read to the first property
            reader.Read();

            while(reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName)
                    throw new InvalidDataException("Key value pair JSON missing property name.");

                var key = reader.GetString();

                reader.Read();
                if (reader.TokenType != JsonTokenType.String)
                    throw new InvalidDataException("Key value pair JSON must only have string values.");

                var value = reader.GetString();

                // To make the existence checks easier in this library don't include null values.
                // That way rest of the library just needs to do ContainsKey check.
                if (value != null)
                {
                    dictionary[key] = value;
                }

                // Move to the next property or end of object
                reader.Read();
            }

            return dictionary;
        }
    }
}
