//
// MonoTlsProviderFactory.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Mono.Net.Security;

namespace Mono.Security.Interface
{
	/*
	 * Public API front-end to System.dll's version.
	 *
	 * Keep in sync with System/Mono.Net.Security/MonoTlsProviderFactory.cs.
	 */
	public static partial class MonoTlsProviderFactory
	{
		/*
		 * Returns the global @MonoTlsProvider, initializing the TLS Subsystem if necessary.
		 *
		 * This method throws @NotSupportedException if no TLS Provider can be found.
		 */
		public static MonoTlsProvider GetProvider ()
		{
			return (MonoTlsProvider)NoReflectionHelper.GetProvider ();
		}

		/*
		 * Check whether the TLS Subsystem is initialized.
		 */
		public static bool IsInitialized {
			get {
				return NoReflectionHelper.IsInitialized;
			}
		}

		/*
		 * Initialize the TLS Subsystem.
		 * 
		 * This method may be called at any time.  It ensures that the TLS Subsystem is
		 * initialized and a provider available.
		 */
		public static void Initialize ()
		{
			NoReflectionHelper.Initialize ();
		}

		/*
		 * Initialize the TLS Subsystem with a specific provider.
		 * 
		 * May only be called at application startup (before any of the TLS / Certificate
		 * APIs have been used).
		 * 
		 * This method throws @NotSupportedException if @IsInitialized returns true.
		 */
		public static void Initialize (string provider)
		{
			NoReflectionHelper.Initialize (provider);
		}

		/*
		 * Call-by-call TLS Provider selection.
		 *
		 */
		public static bool IsProviderSupported (string name)
		{
			return NoReflectionHelper.IsProviderSupported (name);
		}

		public static MonoTlsProvider GetProvider (string name)
		{
			return (MonoTlsProvider)NoReflectionHelper.GetProvider (name);
		}

		/*
		 * Create @HttpWebRequest with the specified @provider (may be null to use the default one).
		 * 
		 * NOTE: This needs to be written as "System.Uri" to avoid ambiguity with Mono.Security.Uri in the
		 *        mobile build.
		 * 
		 */
		public static HttpWebRequest CreateHttpsRequest (System.Uri requestUri, MonoTlsProvider provider = null, MonoTlsSettings settings = null)
		{
			return NoReflectionHelper.CreateHttpsRequest (requestUri, provider, settings);
		}

		public static HttpListener CreateHttpListener (X509Certificate certificate, MonoTlsProvider provider = null, MonoTlsSettings settings = null)
		{
			return (HttpListener)NoReflectionHelper.CreateHttpListener (certificate, provider, settings);
		}

		public static IMonoSslStream GetMonoSslStream (SslStream stream)
		{
			return (IMonoSslStream)NoReflectionHelper.GetMonoSslStream (stream);
		}
	}
}

