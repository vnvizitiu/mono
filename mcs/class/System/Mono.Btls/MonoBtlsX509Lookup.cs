//
// MonoBtlsX509Lookup.cs
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
	class MonoBtlsX509Lookup : MonoBtlsObject
	{
		internal class BoringX509LookupHandle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				mono_btls_x509_lookup_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_lookup_free (IntPtr handle);
		}

		new internal BoringX509LookupHandle Handle {
			get { return (BoringX509LookupHandle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringX509LookupHandle mono_btls_x509_lookup_new (MonoBtlsX509Store.BoringX509StoreHandle store, MonoBtlsX509LookupMethod.BoringX509LookupMethodHandle method);

		[DllImport (DLL)]
		extern static int mono_btls_x509_lookup_load_file (BoringX509LookupHandle handle, string file, MonoBtlsX509FileType type);

		[DllImport (DLL)]
		extern static int mono_btls_x509_lookup_add_dir (BoringX509LookupHandle handle, string dir, MonoBtlsX509FileType type);

		[DllImport (DLL)]
		extern static int mono_btls_x509_lookup_init (BoringX509LookupHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_lookup_shutdown (BoringX509LookupHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_x509_lookup_by_subject (BoringX509LookupHandle handle, MonoBtlsX509Name.BoringX509NameHandle name);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_x509_lookup_by_fingerprint (BoringX509LookupHandle handle, IntPtr bytes, int len);

		internal MonoBtlsX509Lookup (BoringX509LookupHandle handle)
			: base (handle)
		{
		}

		internal MonoBtlsX509Lookup (MonoBtlsX509Store store, MonoBtlsX509LookupMethod method)
			: base (mono_btls_x509_lookup_new (store.Handle, method.Handle))
		{
		}

		public void LoadFile (string file, MonoBtlsX509FileType type)
		{
			var ret = mono_btls_x509_lookup_load_file (Handle, file, type);
			CheckError (ret);
		}

		public void AddDirectory (string dir, MonoBtlsX509FileType type)
		{
			var ret = mono_btls_x509_lookup_add_dir (Handle, dir, type);
			CheckError (ret);
		}

		public void Initialize ()
		{
			var ret = mono_btls_x509_lookup_init (Handle);
			CheckError (ret);
		}

		public void Shutdown ()
		{
			var ret = mono_btls_x509_lookup_shutdown (Handle);
			CheckError (ret);
		}

		public MonoBtlsX509 LookupBySubject (MonoBtlsX509Name name)
		{
			var handle = mono_btls_x509_lookup_by_subject (Handle, name.Handle);
			if (handle == null || handle.IsInvalid)
				return null;
			return new MonoBtlsX509 (handle);
		}

		public MonoBtlsX509 LookupByFingerPrint (byte[] fingerprint)
		{
			var bytes = Marshal.AllocHGlobal (fingerprint.Length);
			try {
				Marshal.Copy (fingerprint, 0, bytes, fingerprint.Length);
				var handle = mono_btls_x509_lookup_by_fingerprint (Handle, bytes, fingerprint.Length);
				if (handle == null || handle.IsInvalid)
					return null;
				return new MonoBtlsX509 (handle);
			} finally {
				if (bytes != IntPtr.Zero)
					Marshal.FreeHGlobal (bytes);
			}
		}
	}
}
#endif
