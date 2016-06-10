//
// MonoBtlsX509Name.cs
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
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace Mono.Btls
{
	class MonoBtlsX509Name : MonoBtlsObject
	{
		internal class BoringX509NameHandle : MonoBtlsHandle
		{
			bool dontFree;

			internal BoringX509NameHandle ()
				: base ()
			{
			}

			internal BoringX509NameHandle (IntPtr handle)
				: base ()
			{
				base.handle = handle;
				this.dontFree = true;
			}

			protected override bool ReleaseHandle ()
			{
				if (!dontFree)
					mono_btls_x509_name_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_name_free (IntPtr handle);
		}

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_print_bio (BoringX509NameHandle handle, MonoBtlsBio.BoringBioHandle bio);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_print_string (BoringX509NameHandle handle, StringBuilder buffer, int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_get_raw_data (BoringX509NameHandle handle, out IntPtr buffer, int use_canon_enc);

		[DllImport (DLL)]
		extern static long mono_btls_x509_name_hash (BoringX509NameHandle handle);

		[DllImport (DLL)]
		extern static long mono_btls_x509_name_hash_old (BoringX509NameHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_get_entry_count (BoringX509NameHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509NameEntryType mono_btls_x509_name_get_entry_type (BoringX509NameHandle name, int index);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_get_entry_oid (BoringX509NameHandle name, int index, StringBuilder buffer, int size);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_get_entry_oid_data (BoringX509NameHandle name, int index, out IntPtr data);

		[DllImport (DLL)]
		extern static int mono_btls_x509_name_get_entry_value (BoringX509NameHandle name, int index, out IntPtr str);

		[DllImport (DLL)]
		extern unsafe static BoringX509NameHandle mono_btls_x509_name_from_data (void* data, int len, int use_canon_enc);

		new internal BoringX509NameHandle Handle {
			get { return (BoringX509NameHandle)base.Handle; }
		}

		internal MonoBtlsX509Name (BoringX509NameHandle handle)
			: base (handle)
		{
		}

		public string GetString ()
		{
			var sb = new StringBuilder (4096);
			var ret = mono_btls_x509_name_print_string (Handle, sb, sb.Capacity);
			CheckError (ret);
			return sb.ToString ();
		}

		public void PrintBio (MonoBtlsBio bio)
		{
			var ret = mono_btls_x509_name_print_bio (Handle, bio.Handle);
			CheckError (ret);
		}

		public byte[] GetRawData (bool use_canon_enc)
		{
			IntPtr data;
			var ret = mono_btls_x509_name_get_raw_data (Handle, out data, use_canon_enc ? 1 : 0);
			CheckError (ret > 0);
			var buffer = new byte [ret];
			Marshal.Copy (data, buffer, 0, ret);
			FreeDataPtr (data);
			return buffer;
		}

		public long GetHash ()
		{
			return mono_btls_x509_name_hash (Handle);
		}

		public long GetHashOld ()
		{
			return mono_btls_x509_name_hash_old (Handle);
		}

		public int GetEntryCount ()
		{
			return mono_btls_x509_name_get_entry_count (Handle);
		}

		public MonoBtlsX509NameEntryType GetEntryType (int index)
		{
			if (index >= GetEntryCount ())
				throw new ArgumentOutOfRangeException ();
			return mono_btls_x509_name_get_entry_type (Handle, index);
		}

		public string GetEntryOid (int index)
		{
			if (index >= GetEntryCount ())
				throw new ArgumentOutOfRangeException ();
			var text = new StringBuilder (256);
			var ret = mono_btls_x509_name_get_entry_oid (Handle, index, text, text.Capacity);
			CheckError (ret > 0);
			return text.ToString ();
		}

		public byte[] GetEntryOidData (int index)
		{
			IntPtr data;
			var ret = mono_btls_x509_name_get_entry_oid_data (Handle, index, out data);
			CheckError (ret > 0);

			var bytes = new byte[ret];
			Marshal.Copy (data, bytes, 0, ret);
			return bytes;
		}

		public unsafe string GetEntryValue (int index)
		{
			if (index >= GetEntryCount ())
				throw new ArgumentOutOfRangeException ();
			IntPtr data;
			var ret = mono_btls_x509_name_get_entry_value (Handle, index, out data);
			if (ret <= 0)
				return null;
			try {
				return new UTF8Encoding ().GetString ((byte*)data, ret);
			} finally {
				if (data != IntPtr.Zero)
					FreeDataPtr (data);
			}
		}

		public static unsafe MonoBtlsX509Name CreateFromData (byte[] data, bool use_canon_enc)
		{
			fixed (void *ptr = data) {
				var handle = mono_btls_x509_name_from_data (ptr, data.Length, use_canon_enc ? 1 : 0);
				if (handle == null || handle.IsInvalid)
					throw new MonoBtlsException ("mono_btls_x509_name_from_data() failed.");
				return new MonoBtlsX509Name (handle);
			}
		}
	}
}

