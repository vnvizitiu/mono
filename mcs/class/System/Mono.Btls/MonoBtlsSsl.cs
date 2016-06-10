//
// MonoBtlsSsl.cs
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
#if SECURITY_DEP
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

#if MONOTOUCH
using MonoTouch;
#endif

namespace Mono.Btls
{
	delegate int MonoBtlsVerifyCallback (MonoBtlsX509StoreCtx ctx);

	class MonoBtlsSsl : MonoBtlsObject
	{
		internal class BoringSslHandle : MonoBtlsHandle
		{
			protected override bool ReleaseHandle ()
			{
				mono_btls_ssl_destroy (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_ssl_destroy (IntPtr handle);
		}

		[DllImport (DLL)]
		extern static BoringSslHandle mono_btls_ssl_new (MonoBtlsSslCtx.BoringSslCtxHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_use_certificate (BoringSslHandle handle, MonoBtlsX509.BoringX509Handle x509);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_use_private_key (BoringSslHandle handle, MonoBtlsKey.BoringKeyHandle key);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_accept (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_connect (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_handshake (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static void mono_btls_ssl_close (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static void mono_btls_ssl_set_bio (BoringSslHandle handle, MonoBtlsBio.BoringBioHandle bio);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_read (BoringSslHandle handle, IntPtr data, int len);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_write (BoringSslHandle handle, IntPtr data, int len);

		[DllImport (DLL)]
		extern static void mono_btls_ssl_test (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_get_version (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static void mono_btls_ssl_set_min_version (BoringSslHandle handle, int version);

		[DllImport (DLL)]
		extern static void mono_btls_ssl_set_max_version (BoringSslHandle handle, int version);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_get_cipher (BoringSslHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_get_ciphers (BoringSslHandle handle, out IntPtr data);

		[DllImport (DLL)]
		extern static int mono_btls_ssl_set_cipher_list (BoringSslHandle handle, string str);

		public MonoBtlsSsl (MonoBtlsSslCtx ctx)
			: base (mono_btls_ssl_new (ctx.Handle))
		{
		}

		new internal BoringSslHandle Handle {
			get { return (BoringSslHandle)base.Handle; }
		}

		public void SetBio (MonoBtlsBio bio)
		{
			CheckThrow ();
			mono_btls_ssl_set_bio (Handle, bio.Handle);
		}

		Exception ThrowError ([CallerMemberName] string callerName = null)
		{
			string errors;
			try {
				if (callerName == null)
					callerName = GetType ().Name;
				errors = GetErrors ();
			} catch {
				errors = null;
			}

			if (errors != null) {
				Console.Error.WriteLine ("ERROR: {0} failed: {1}", callerName, errors);
				throw new MonoBtlsException ("{0} failed: {1}.", callerName, errors);
			} else {
				Console.Error.WriteLine ("ERROR: {0} failed.", callerName);
				throw new MonoBtlsException ("{0} failed.", callerName);
			}
		}

		public void SetCertificate (MonoBtlsX509 x509)
		{
			CheckThrow ();

			var ret = mono_btls_ssl_use_certificate (Handle, x509.Handle);
			if (ret <= 0)
				throw ThrowError ();
		}

		public void SetPrivateKey (MonoBtlsKey key)
		{
			CheckThrow ();

			var ret = mono_btls_ssl_use_private_key (Handle, key.Handle);
			if (ret <= 0)
				throw ThrowError ();
		}

		public void Accept ()
		{
			CheckThrow ();

			var ret = mono_btls_ssl_accept (Handle);
			Console.WriteLine (ret);
			if (ret <= 0)
				throw ThrowError ();
		}

		public void Connect ()
		{
			CheckThrow ();

			var ret = mono_btls_ssl_connect (Handle);
			Console.WriteLine (ret);
			if (ret <= 0)
				throw ThrowError ();
		}

		public void Handshake ()
		{
			CheckThrow ();

			var ret = mono_btls_ssl_handshake (Handle);
			Console.WriteLine (ret);
			if (ret <= 0)
				throw ThrowError ();
		}

		delegate int PrintErrorsCallbackFunc (IntPtr str, IntPtr len, IntPtr ctx);

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (PrintErrorsCallbackFunc))]
#endif
		static int PrintErrorsCallback (IntPtr str, IntPtr len, IntPtr ctx)
		{
			var sb = (StringBuilder)GCHandle.FromIntPtr (ctx).Target;
			try {
				var text = Marshal.PtrToStringAnsi (str, (int)len);
				sb.Append (text);
				return 1;
			} catch {
				return 0;
			}
		}

		[DllImport (DLL)]
		extern static void mono_btls_ssl_print_errors_cb (PrintErrorsCallbackFunc func, IntPtr ctx);

		public string GetErrors ()
		{
			var text = new StringBuilder ();
			var handle = GCHandle.Alloc (text);

			try {
				PrintErrorsCallbackFunc func = PrintErrorsCallback;
				mono_btls_ssl_print_errors_cb (func, GCHandle.ToIntPtr (handle));
				return text.ToString ();
			} finally {
				if (handle.IsAllocated)
					handle.Free ();
			}
		}

		public void PrintErrors ()
		{
			var errors = GetErrors ();
			if (string.IsNullOrEmpty (errors))
				return;
			Console.Error.WriteLine (errors);
		}

		public int Read (byte[] buffer, int offset, int size)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				var ret = mono_btls_ssl_read (Handle, data, size);
				if (ret > 0)
					Marshal.Copy (data, buffer,offset, ret);
				return ret;
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public int Write (byte[] buffer, int offset, int size)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				Marshal.Copy (buffer, offset, data, size);
				return mono_btls_ssl_write (Handle, data, size);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public int GetVersion ()
		{
			CheckThrow ();
			return mono_btls_ssl_get_version (Handle);
		}

		public void SetMinVersion (int version)
		{
			CheckThrow ();
			mono_btls_ssl_set_min_version (Handle, version);
		}

		public void SetMaxVersion (int version)
		{
			CheckThrow ();
			mono_btls_ssl_set_max_version (Handle, version);
		}

		public int GetCipher ()
		{
			CheckThrow ();
			var cipher = mono_btls_ssl_get_cipher (Handle);
			CheckError (cipher > 0);
			return cipher;
		}

		public short[] GetCiphers ()
		{
			CheckThrow ();
			IntPtr data;
			var count = mono_btls_ssl_get_ciphers (Handle, out data);
			CheckError (count > 0);
			try {
				short[] ciphers = new short[count];
				Marshal.Copy (data, ciphers, 0, count);
				return ciphers;
			} finally {
				FreeDataPtr (data);
			}
		}

		public void SetCipherList (string str)
		{
			CheckThrow ();
			var ret = mono_btls_ssl_set_cipher_list (Handle, str);
			CheckError (ret);
		}

		public void Test ()
		{
			CheckThrow ();
			mono_btls_ssl_test (Handle);
		}

		protected override void Close ()
		{
			mono_btls_ssl_close (Handle);
		}
	}
}
#endif
