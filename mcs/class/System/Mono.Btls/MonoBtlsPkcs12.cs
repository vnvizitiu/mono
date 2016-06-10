//
// MonoBtlsPkcs12.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin Inc. (http://www.xamarin.com)
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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace Mono.Btls
{
	class MonoBtlsPkcs12 : MonoBtlsObject
	{
		internal class BoringPkcs12Handle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				mono_btls_pkcs12_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_pkcs12_free (IntPtr handle);
		}

		new internal BoringPkcs12Handle Handle {
			get { return (BoringPkcs12Handle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringPkcs12Handle mono_btls_pkcs12_new ();

		[DllImport (DLL)]
		extern static int mono_btls_pkcs12_get_count (BoringPkcs12Handle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_pkcs12_get_cert (BoringPkcs12Handle Handle, int index);

		[DllImport (DLL)]
		extern static int mono_btls_pkcs12_add_cert (BoringPkcs12Handle chain, MonoBtlsX509.BoringX509Handle x509);

		[DllImport (DLL)]
		extern unsafe static int mono_btls_pkcs12_import (BoringPkcs12Handle chain, void* data, int len, IntPtr password);

		[DllImport (DLL)]
		extern static int mono_btls_pkcs12_has_private_key (BoringPkcs12Handle pkcs12);

		[DllImport (DLL)]
		extern static MonoBtlsKey.BoringKeyHandle mono_btls_pkcs12_get_private_key (BoringPkcs12Handle pkcs12);

		internal MonoBtlsPkcs12 ()
			: base (mono_btls_pkcs12_new ())
		{
		}

		internal MonoBtlsPkcs12 (BoringPkcs12Handle handle)
			: base (handle)
		{
		}

		MonoBtlsKey privateKey;

		public int Count {
			get { return mono_btls_pkcs12_get_count (Handle); }
		}

		public MonoBtlsX509 GetCertificate (int index)
		{
			if (index >= Count)
				throw new IndexOutOfRangeException ();
			var handle = mono_btls_pkcs12_get_cert (Handle, index);
			CheckError (handle != null);
			return new MonoBtlsX509 (handle);
		}

#if MARTIN_TEST
		public void Dump ()
		{
			Console.Error.WriteLine ("CHAIN: {0:x} {1}", Handle, Count);
			for (int i = 0; i < Count; i++) {
				using (var cert = GetCertificate (i)) {
					var bcert = new X509CertificateImplBoring (cert);
					var mcert = new X509Certificate (bcert);
					Console.Error.WriteLine ("CERT: {0} - {1}", cert.GetSubjectName (), mcert.ToString (true));
					MartinTest.PrintCertificate (mcert);
				}
			}
		}
#endif

		public void AddCertificate (MonoBtlsX509 x509)
		{
			mono_btls_pkcs12_add_cert (Handle, x509.Handle);
		}

		public unsafe void Import (byte[] buffer, string password)
		{
			var passptr = IntPtr.Zero;
			fixed (void* ptr = buffer)
			try {
				passptr = Marshal.StringToHGlobalAnsi (password ?? string.Empty);
				var ret = mono_btls_pkcs12_import (Handle, ptr, buffer.Length, passptr);
				CheckError (ret);
			} finally {
				if (passptr != IntPtr.Zero)
					Marshal.FreeHGlobal (passptr);
			}
		}

		public bool HasPrivateKey {
			get { return mono_btls_pkcs12_has_private_key (Handle) != 0; }
		}

		public MonoBtlsKey GetPrivateKey ()
		{
			if (!HasPrivateKey)
				throw new InvalidOperationException ();
			if (privateKey == null) {
				var handle = mono_btls_pkcs12_get_private_key (Handle);
				CheckError (handle != null && !handle.IsInvalid);
				privateKey = new MonoBtlsKey (handle);
			}
			return privateKey;
		}
	}
}

