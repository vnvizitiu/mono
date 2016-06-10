//
// MonoBtlsX509.cs
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
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Mono.Btls
{
	class MonoBtlsX509 : MonoBtlsObject
	{
		internal class BoringX509Handle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				if (handle != IntPtr.Zero)
					mono_btls_x509_free (handle);
				return true;
			}

			public IntPtr StealHandle ()
			{
				var retval = Interlocked.Exchange (ref handle, IntPtr.Zero);
				return retval;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_free (IntPtr handle);
		}

		new internal BoringX509Handle Handle {
			get { return (BoringX509Handle)base.Handle; }
		}

		internal MonoBtlsX509 (BoringX509Handle handle) 
			: base (handle)
		{
		}

		public void Test ()
		{
			mono_btls_x509_test (Handle);
		}

		internal MonoBtlsX509 Copy ()
		{
			return new MonoBtlsX509 (mono_btls_x509_up_ref (Handle));
		}

		[DllImport (DLL)]
		extern static BoringX509Handle mono_btls_x509_up_ref (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static void mono_btls_x509_test (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static BoringX509Handle mono_btls_x509_from_data (IntPtr data, int len, MonoBtlsX509Format format);

		public static MonoBtlsX509 LoadFromData (byte[] buffer, MonoBtlsX509Format format)
		{
			var data = Marshal.AllocHGlobal (buffer.Length);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				Marshal.Copy (buffer, 0, data, buffer.Length);
				var x509 = mono_btls_x509_from_data (data, buffer.Length, format);
				if (x509 == null || x509.IsInvalid)
					throw new MonoBtlsException ("Failed to read certificate from data.");

				return new MonoBtlsX509 (x509);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		[DllImport (DLL)]
		extern static MonoBtlsX509Name.BoringX509NameHandle mono_btls_x509_get_subject_name (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509Name.BoringX509NameHandle mono_btls_x509_get_issuer_name (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_subject_name_string (BoringX509Handle handle, StringBuilder buffer, int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_issuer_name_string (BoringX509Handle handle, StringBuilder buffer, int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_raw_data (BoringX509Handle handle, MonoBtlsBio.BoringBioHandle bio);

		[DllImport (DLL)]
		extern static int mono_btls_x509_cmp (BoringX509Handle a, BoringX509Handle b);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_hash (BoringX509Handle handle, out IntPtr data);

		[DllImport (DLL)]
		extern static long mono_btls_x509_get_not_before (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static long mono_btls_x509_get_not_after (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_public_key (BoringX509Handle handle, MonoBtlsBio.BoringBioHandle bio);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_serial_number (BoringX509Handle handle, IntPtr data, int size, int mono_style);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_version (BoringX509Handle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_signature_algorithm (BoringX509Handle handle, StringBuilder buffer, int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_public_key_asn1 (BoringX509Handle handle, StringBuilder oid, int oid_size, out IntPtr data, out int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_get_public_key_parameters (BoringX509Handle handle, StringBuilder oid, int oid_size, out IntPtr data, out int size);

		[DllImport (DLL)]
		extern static MonoBtlsKey.BoringKeyHandle mono_btls_x509_get_pubkey (BoringX509Handle handle);

		public MonoBtlsX509Name GetSubjectName ()
		{
			return new MonoBtlsX509Name (mono_btls_x509_get_subject_name (Handle));
		}

		public string GetSubjectNameString ()
		{
			var sb = new StringBuilder (4096);
			var ret = mono_btls_x509_get_subject_name_string (Handle, sb, sb.Capacity);
			CheckError (ret);
			return sb.ToString ();
		}

		public MonoBtlsX509Name GetIssuerName ()
		{
			return new MonoBtlsX509Name (mono_btls_x509_get_issuer_name (Handle));
		}

		public string GetIssuerNameString ()
		{
			var sb = new StringBuilder (4096);
			var ret = mono_btls_x509_get_issuer_name_string (Handle, sb, sb.Capacity);
			CheckError (ret);
			return sb.ToString ();
		}

		public byte[] GetRawData ()
		{
			using (var bio = new MonoBtlsBioMemory ()) {
				var ret = mono_btls_x509_get_raw_data (Handle, bio.Handle);
				CheckError (ret);
				return bio.GetData ();
			}
		}

		public static int Compare (MonoBtlsX509 a, MonoBtlsX509 b)
		{
			return mono_btls_x509_cmp (a.Handle, b.Handle);
		}

		public byte[] GetCertHash ()
		{
			IntPtr data;
			var ret = mono_btls_x509_get_hash (Handle, out data);
			CheckError (ret > 0);
			var buffer = new byte [ret];
			Marshal.Copy (data, buffer, 0, ret);
			return buffer;
		}

		public DateTime GetNotBefore ()
		{
			var ticks = mono_btls_x509_get_not_before (Handle);
			return new DateTime (1970, 1, 1).AddSeconds (ticks);
		}

		public DateTime GetNotAfter ()
		{
			var ticks = mono_btls_x509_get_not_after (Handle);
			return new DateTime (1970, 1, 1).AddSeconds (ticks);
		}

		public byte[] GetPublicKeyData ()
		{
			using (var bio = new MonoBtlsBioMemory ()) {
				var ret = mono_btls_x509_get_public_key (Handle, bio.Handle);
				CheckError (ret > 0);
				return bio.GetData ();
			}
		}

		public byte[] GetSerialNumber (bool mono_style)
		{
			int size = 256;
			IntPtr data = Marshal.AllocHGlobal (size);
			try {
				var ret = mono_btls_x509_get_serial_number (Handle, data, size, mono_style ? 1 : 0);
				CheckError (ret > 0);
				var buffer = new byte [ret];
				Marshal.Copy (data, buffer, 0, ret);
				return buffer;
			} finally {
				if (data != IntPtr.Zero)
					Marshal.FreeHGlobal (data);
			}
		}

		public int GetVersion ()
		{
			return mono_btls_x509_get_version (Handle);
		}

		public Oid GetSignatureAlgorithm ()
		{
			var sb = new StringBuilder (256);
			var ret = mono_btls_x509_get_signature_algorithm (Handle, sb, sb.Capacity);
			CheckError (ret > 0);
			return new Oid (sb.ToString ());
		}

		public AsnEncodedData GetPublicKeyAsn1 ()
		{
			int size;
			IntPtr data;
			var oid = new StringBuilder (256);
			var ret = mono_btls_x509_get_public_key_asn1 (Handle, oid, oid.Capacity, out data, out size);
			CheckError (ret);

			try {
				var buffer = new byte[size];
				Marshal.Copy (data, buffer, 0, size);
				return new AsnEncodedData (oid.ToString (), buffer);
			} finally {
				if (data != IntPtr.Zero)
					FreeDataPtr (data);
			}
		}

		public AsnEncodedData GetPublicKeyParameters ()
		{
			int size;
			IntPtr data;
			var oid = new StringBuilder (256);
			var ret = mono_btls_x509_get_public_key_parameters (Handle, oid, oid.Capacity, out data, out size);
			CheckError (ret);

			try {
				var buffer = new byte[size];
				Marshal.Copy (data, buffer, 0, size);
				return new AsnEncodedData (oid.ToString (), buffer);
			} finally {
				if (data != IntPtr.Zero)
					FreeDataPtr (data);
			}
		}

		public MonoBtlsKey GetPublicKey ()
		{
			var handle = mono_btls_x509_get_pubkey (Handle);
			CheckError (handle != null && !handle.IsInvalid);
			return new MonoBtlsKey (handle);
		}
	}
}
#endif
