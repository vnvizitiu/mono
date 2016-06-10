//
// MonoBtlsX509VerifyParam.cs
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
	class MonoBtlsX509VerifyParam : MonoBtlsObject
	{
		internal class BoringX509VerifyParamHandle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				mono_btls_x509_verify_param_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_verify_param_free (IntPtr handle);
		}

		new internal BoringX509VerifyParamHandle Handle {
			get { return (BoringX509VerifyParamHandle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringX509VerifyParamHandle mono_btls_x509_verify_param_new ();

		[DllImport (DLL)]
		extern static BoringX509VerifyParamHandle mono_btls_x509_verify_param_copy (BoringX509VerifyParamHandle handle);

		[DllImport (DLL)]
		extern static BoringX509VerifyParamHandle mono_btls_x509_verify_param_lookup (string name);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_can_modify (BoringX509VerifyParamHandle param);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_name (BoringX509VerifyParamHandle handle, string name);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_host (BoringX509VerifyParamHandle handle, string name, int namelen);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_add_host (BoringX509VerifyParamHandle handle, string name, int namelen);

		[DllImport (DLL)]
		extern static ulong mono_btls_x509_verify_param_get_flags (BoringX509VerifyParamHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_flags (BoringX509VerifyParamHandle handle, ulong flags);

		[DllImport (DLL)]
		extern static MonoBtlsX509VerifyFlags mono_btls_x509_verify_param_get_mono_flags (BoringX509VerifyParamHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_mono_flags (BoringX509VerifyParamHandle handle, MonoBtlsX509VerifyFlags flags);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_purpose (BoringX509VerifyParamHandle handle, MonoBtlsX509Purpose purpose);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_get_depth (BoringX509VerifyParamHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_depth (BoringX509VerifyParamHandle handle, int depth);

		[DllImport (DLL)]
		extern static int mono_btls_x509_verify_param_set_time (BoringX509VerifyParamHandle handle, long time);

		[DllImport (DLL)]
		extern static IntPtr mono_btls_x509_verify_param_get_peername (BoringX509VerifyParamHandle handle);


		internal MonoBtlsX509VerifyParam ()
			: base (mono_btls_x509_verify_param_new ())
		{
		}

		internal MonoBtlsX509VerifyParam (BoringX509VerifyParamHandle handle)
			: base (handle)
		{
		}

		public MonoBtlsX509VerifyParam Copy ()
		{
			var copy = mono_btls_x509_verify_param_copy (Handle);
			CheckError (copy != null && !copy.IsInvalid);
			return new MonoBtlsX509VerifyParam (copy);
		}

		public static MonoBtlsX509VerifyParam GetSslClient ()
		{
			return Lookup ("ssl_client", true);
		}

		public static MonoBtlsX509VerifyParam GetSslServer ()
		{
			return Lookup ("ssl_server", true);
		}

		public static MonoBtlsX509VerifyParam Lookup (string name, bool fail = false)
		{
			var handle = mono_btls_x509_verify_param_lookup (name);
			if (handle == null || handle.IsInvalid) {
				if (!fail)
					return null;
				throw new MonoBtlsException ("X509_VERIFY_PARAM_lookup() could not find '{0}'.", name);
			}

			return new MonoBtlsX509VerifyParam (handle);
		}

		public bool CanModify {
			get {
				return mono_btls_x509_verify_param_can_modify (Handle) != 0;
			}
		}

		void WantToModify ()
		{
			if (!CanModify)
				throw new MonoBtlsException ("Attempting to modify read-only MonoBtlsX509VerifyParam instance.");
		}

		public void SetName (string name)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_name (Handle, name);
			CheckError (ret);
		}

		public void SetHost (string name)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_host (Handle, name, name.Length);
			CheckError (ret);
		}

		public void AddHost (string name)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_add_host (Handle, name, name.Length);
			CheckError (ret);
		}

		public ulong GetFlags ()
		{
			return mono_btls_x509_verify_param_get_flags (Handle);
		}

		public void SetFlags (ulong flags)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_flags (Handle, flags);
			CheckError (ret);
		}

		public MonoBtlsX509VerifyFlags GetMonoFlags ()
		{
			return mono_btls_x509_verify_param_get_mono_flags (Handle);	
		}

		public void SetMonoFlags (MonoBtlsX509VerifyFlags flags)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_mono_flags (Handle, flags);
			CheckError (ret);
		}

		public void SetPurpose (MonoBtlsX509Purpose purpose)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_purpose (Handle, purpose);
			CheckError (ret);
		}

		public int GetDepth ()
		{
			return mono_btls_x509_verify_param_get_depth (Handle);
		}

		public void SetDepth (int depth)
		{
			WantToModify ();
			var ret = mono_btls_x509_verify_param_set_depth (Handle, depth);
			CheckError (ret);
		}

		public void SetTime (DateTime time)
		{
			WantToModify ();
			var epoch = new DateTime (1970, 1, 1);
			var ticks = (long)time.Subtract (epoch).TotalSeconds;
			var ret = mono_btls_x509_verify_param_set_time (Handle, ticks);
			CheckError (ret);
		}

		public string GetPeerName ()
		{
			var peer = mono_btls_x509_verify_param_get_peername (Handle);
			if (peer == IntPtr.Zero)
				return null;
			return Marshal.PtrToStringAnsi (peer);
		}
	}
}
#endif
