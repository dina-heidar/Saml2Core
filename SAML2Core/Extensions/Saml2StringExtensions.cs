//MIT License

//Copyright (c) 2018 Dina Heidar

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Web;
using static SamlCore.AspNetCore.Authentication.Saml2.Saml2Constants;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public static class Saml2StringExtensions
    {
        /// <summary>
        /// Base64s the encode.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <returns></returns>
        internal static string Base64Encode(this string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        /// <summary>
        /// Base64s the decode.
        /// </summary>
        /// <param name="base64EncodedData">The base64 encoded data.</param>
        /// <returns></returns>
        internal static string Base64Decode(this string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        /// <summary>
        /// Deflates the encode.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string DeflateEncode(this string value)
        {
            var memoryStream = new MemoryStream();
            using (var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true),
                new UTF8Encoding(false)))
            {
                writer.Write(value);
                writer.Close();
                return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length,
                    Base64FormattingOptions.None);
            }
        }

        /// <summary>
        /// URLs the encode.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string UrlEncode(this string value)
        {
            return HttpUtility.UrlEncode(value);
        }

        /// <summary>
        /// Uppers the case URL encode.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string UpperCaseUrlEncode(this string value)
        {
            var result = new StringBuilder(value);
            for (var i = 0; i < result.Length; i++)
                if (result[i] == '%')
                {
                    result[++i] = char.ToUpper(result[i]);
                    result[++i] = char.ToUpper(result[i]);
                }
            return result.ToString();
        }
        /// <summary>
        /// Deflates the decompress.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static string DeflateDecompress(this string value)
        {
            var encoded = Convert.FromBase64String(value);
            var memoryStream = new MemoryStream(encoded);

            var result = new StringBuilder();
            using (var stream = new DeflateStream(memoryStream, CompressionMode.Decompress))
            {
                var testStream = new StreamReader(new BufferedStream(stream), Encoding.UTF8);
                // It seems we need to "peek" on the StreamReader to get it started. If we don't do this, the first call to 
                // ReadToEnd() will return string.empty.
                var peek = testStream.Peek();
                result.Append(testStream.ReadToEnd());

                stream.Close();
            }
            return result.ToString();
        }
        /// <summary>
        /// Adds the message parameter.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <param name="request">The request.</param>
        /// <param name="response">The response.</param>
        /// <exception cref="Exception">Request or Response property MUST be set.</exception>
        public static void AddMessageParameter(this StringBuilder result, string request, string response)
        {
            if (!(response == null || request == null))
                throw new Exception("Request or Response property MUST be set.");

            string value;
            if (request != null)
            {
                result.AppendFormat("{0}=", Parameters.SamlRequest);
                value = request;
            }
            else
            {
                result.AppendFormat("{0}=", Parameters.SamlResponse);
                value = response;
            }
            var encoded = value.DeflateEncode();
            var urlEncoded = encoded.UrlEncode();
            result.Append(urlEncoded.UpperCaseUrlEncode());
        }

        /// <summary>
        /// Adds the state of the relay.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <param name="request">The request.</param>
        /// <param name="relayState">State of the relay.</param>
        public static void AddRelayState(this StringBuilder result, string request, string relayState)
        {
            if (relayState == null)
                return;

            result.Append("&RelayState=");
            // Encode the relay state if we're building a request. Otherwise, append unmodified.
            result.Append(request != null ? relayState.DeflateEncode().UrlEncode() : relayState);
        }
    }
}