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
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public static class HttpExtensions
    {
        /// <summary>
        /// Deletes all request identifier cookies.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="request">The request.</param>
        /// <param name="samlCookieName">Name of the saml cookie.</param>
        public static void DeleteAllRequestIdCookies(this HttpResponse response, HttpRequest request, string samlCookieName)
        {
            var cookies = request.Cookies;
            foreach (var cookie in cookies.Where(c => c.Key.StartsWith(samlCookieName)))
            {
                response.Cookies.Append(cookie.Key, "", new CookieOptions() { Expires = DateTime.Now.AddDays(-1) });
                response.Cookies.Delete(cookie.Key);
            }
        }
    }
}