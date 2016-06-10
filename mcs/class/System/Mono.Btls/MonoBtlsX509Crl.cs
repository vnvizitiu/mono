//
// MonoBtlsX509Crl.cs
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
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Mono.Btls
{
	class MonoBtlsX509Crl : MonoBtlsObject
	{
		internal class BoringX509CrlHandle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				if (handle != IntPtr.Zero)
					mono_btls_x509_crl_free (handle);
				return true;
			}

			public IntPtr StealHandle ()
			{
				var retval = Interlocked.Exchange (ref handle, IntPtr.Zero);
				return retval;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_crl_free (IntPtr handle);
		}

		new internal BoringX509CrlHandle Handle {
			get { return (BoringX509CrlHandle)base.Handle; }
		}

		internal MonoBtlsX509Crl (BoringX509CrlHandle handle) 
			: base (handle)
		{
		}

		[DllImport (DLL)]
		extern static BoringX509CrlHandle mono_btls_x509_crl_ref (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static void mono_btls_x509_crl_test (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static BoringX509CrlHandle mono_btls_x509_crl_from_data (IntPtr data, int len, MonoBtlsX509Format format);

		[DllImport (DLL)]
		extern static MonoBtlsX509Revoked.BoringX509RevokedHandle mono_btls_x509_crl_get_by_cert (BoringX509CrlHandle handle, MonoBtlsX509.BoringX509Handle x509);

		[DllImport (DLL)]
		unsafe extern static MonoBtlsX509Revoked.BoringX509RevokedHandle mono_btls_x509_crl_get_by_serial (BoringX509CrlHandle handle, void *serial, int len);

		[DllImport (DLL)]
		extern static int mono_btls_x509_crl_get_revoked_count (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509Revoked.BoringX509RevokedHandle mono_btls_x509_crl_get_revoked (BoringX509CrlHandle handle, int index);

		[DllImport (DLL)]
		extern static long mono_btls_x509_crl_get_last_update (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static long mono_btls_x509_crl_get_next_update (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static long mono_btls_x509_crl_get_version (BoringX509CrlHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509Name.BoringX509NameHandle mono_btls_x509_crl_get_issuer (BoringX509CrlHandle handle);

		public static MonoBtlsX509Crl LoadFromData (byte[] buffer, MonoBtlsX509Format format)
		{
			var data = Marshal.AllocHGlobal (buffer.Length);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				Marshal.Copy (buffer, 0, data, buffer.Length);
				var crl = mono_btls_x509_crl_from_data (data, buffer.Length, format);
				if (crl == null || crl.IsInvalid)
					throw new MonoBtlsException ("Failed to read CRL from data.");

				return new MonoBtlsX509Crl (crl);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public MonoBtlsX509Revoked GetByCert (MonoBtlsX509 x509)
		{
			var revoked = mono_btls_x509_crl_get_by_cert (Handle, x509.Handle);
			if (revoked == null || revoked.IsInvalid)
				return null;
			return new MonoBtlsX509Revoked (revoked);
		}

		public unsafe MonoBtlsX509Revoked GetBySerial (byte[] serial)
		{
			fixed (void *ptr = serial)
			{
				var revoked = mono_btls_x509_crl_get_by_serial (Handle, ptr, serial.Length);
				if (revoked == null || revoked.IsInvalid)
					return null;
				return new MonoBtlsX509Revoked (revoked);
			}
		}

		public int GetRevokedCount ()
		{
			return mono_btls_x509_crl_get_revoked_count (Handle);
		}

		public MonoBtlsX509Revoked GetRevoked (int index)
		{
			if (index >= GetRevokedCount ())
				throw new ArgumentOutOfRangeException ();

			var revoked = mono_btls_x509_crl_get_revoked (Handle, index);
			if (revoked == null || revoked.IsInvalid)
				return null;
			return new MonoBtlsX509Revoked (revoked);
		}

		public DateTime GetLastUpdate ()
		{
			var ticks = mono_btls_x509_crl_get_last_update (Handle);
			return new DateTime (1970, 1, 1).AddSeconds (ticks);
		}

		public DateTime GetNextUpdate ()
		{
			var ticks = mono_btls_x509_crl_get_next_update (Handle);
			return new DateTime (1970, 1, 1).AddSeconds (ticks);
		}

		public long GetVersion ()
		{
			return mono_btls_x509_crl_get_version (Handle);
		}

		public MonoBtlsX509Name GetIssuerName ()
		{
			return new MonoBtlsX509Name (mono_btls_x509_crl_get_issuer (Handle));
		}
	}

}

