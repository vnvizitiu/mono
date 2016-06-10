//
// MonoBtlsX509Store.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2016 Xamarin Inc. (http://www.xamarin.com)
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
#if SECURITY_DEP
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace Mono.Btls
{
	class MonoBtlsX509Store : MonoBtlsObject
	{
		internal class BoringX509StoreHandle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				mono_btls_x509_store_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_store_free (IntPtr handle);
		}

		new internal BoringX509StoreHandle Handle {
			get { return (BoringX509StoreHandle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringX509StoreHandle mono_btls_x509_store_new ();

		[DllImport (DLL)]
		extern static BoringX509StoreHandle mono_btls_x509_store_from_ctx (IntPtr ctx);

		[DllImport (DLL)]
		extern static BoringX509StoreHandle mono_btls_x509_store_from_ssl_ctx (MonoBtlsSslCtx.BoringSslCtxHandle handle);

		[DllImport (DLL, CharSet = CharSet.Auto)]
		extern static int mono_btls_x509_store_load_locations (BoringX509StoreHandle handle, string file, string path);

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_set_default_paths (BoringX509StoreHandle handle);

		public void LoadLocations (string file, string path)
		{
			var ret = mono_btls_x509_store_load_locations (Handle, file, path);
			CheckError (ret);
		}

		public void SetDefaultPaths ()
		{
			var ret = mono_btls_x509_store_set_default_paths (Handle);
			CheckError (ret);
		}

		internal MonoBtlsX509Store ()
			: base (mono_btls_x509_store_new ())
		{
		}

		internal MonoBtlsX509Store (IntPtr store_ctx)
			: base (mono_btls_x509_store_from_ctx (store_ctx))
		{
		}

		internal MonoBtlsX509Store (MonoBtlsSslCtx.BoringSslCtxHandle handle)
			: base (mono_btls_x509_store_from_ssl_ctx (handle))
		{
		}

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_add_cert (BoringX509StoreHandle handle, MonoBtlsX509.BoringX509Handle x509);

		public void AddTrustAnchor (MonoBtlsX509 x509)
		{
			var ret = mono_btls_x509_store_add_cert (Handle, x509.Handle);
			CheckError (ret);
		}

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_get_count (BoringX509StoreHandle handle);

		public int GetCount ()
		{
			return mono_btls_x509_store_get_count (Handle);
		}

		internal void AddTrustedRoots ()
		{
			var systemRoot = MonoBtlsProvider.GetSystemStoreLocation ();
			LoadLocations (null, systemRoot);
		}
	}
}
#endif
