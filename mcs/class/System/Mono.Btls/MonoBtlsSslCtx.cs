//
// MonoBtlsSslCtx.cs
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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Mono.Btls
{
	class MonoBtlsSslCtx : MonoBtlsObject
	{
		internal class BoringSslCtxHandle : MonoBtlsHandle
		{
			public BoringSslCtxHandle (IntPtr handle)
				: base (handle, true)
			{
			}

			protected override bool ReleaseHandle ()
			{
				mono_btls_ssl_ctx_free (handle);
				return true;
			}
		}

		new internal BoringSslCtxHandle Handle {
			get { return (BoringSslCtxHandle)base.Handle; }
		}

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_ssl_ctx_new ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_ssl_ctx_free (IntPtr handle);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_ssl_ctx_up_ref (IntPtr handle);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_ssl_ctx_set_debug_bio (IntPtr handle, IntPtr bio);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_ssl_ctx_set_cert_verify_callback (IntPtr handle, IntPtr func);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_ssl_ctx_set_min_version (IntPtr handle, int version);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_ssl_ctx_set_max_version (IntPtr handle, int version);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_ssl_ctx_is_cipher_supported (IntPtr handle, short value);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_ssl_ctx_set_ciphers (IntPtr handle, int count, IntPtr data, int allow_unsupported);

		delegate int NativeVerifyFunc (int preverify_ok, IntPtr ctx);

		NativeVerifyFunc verifyFunc;
		IntPtr verifyFuncPtr;
		MonoBtlsVerifyCallback verifyCallback;
		MonoBtlsX509Store store;

		public MonoBtlsSslCtx ()
			: base (new BoringSslCtxHandle (mono_btls_ssl_ctx_new ()))
		{
			verifyFunc = NativeVerifyCallback;
			verifyFuncPtr = Marshal.GetFunctionPointerForDelegate (verifyFunc);
			store = new MonoBtlsX509Store (Handle);
		}

		internal MonoBtlsSslCtx (BoringSslCtxHandle handle)
			: base (handle)
		{
			verifyFunc = NativeVerifyCallback;
			verifyFuncPtr = Marshal.GetFunctionPointerForDelegate (verifyFunc);
			store = new MonoBtlsX509Store (Handle);
		}

		internal MonoBtlsSslCtx Copy ()
		{
			var copy = mono_btls_ssl_ctx_up_ref (Handle.DangerousGetHandle ());
			return new MonoBtlsSslCtx (new BoringSslCtxHandle (copy));
		}

		public MonoBtlsX509Store CertificateStore {
			get { return store; }
		}

		int NativeVerifyCallback (int preverify_ok, IntPtr store_ctx)
		{
			using (var ctx = new MonoBtlsX509StoreCtx (preverify_ok, store_ctx)) {
				try {
					if (verifyCallback != null)
						return verifyCallback (ctx);
				} catch (Exception ex) {
					SetException (ex);
				}
			}
			return 0;
		}

		public void SetDebugBio (MonoBtlsBio bio)
		{
			CheckThrow ();
			mono_btls_ssl_ctx_set_debug_bio (Handle.DangerousGetHandle (), bio.Handle.DangerousGetHandle ());
		}

		public void SetVerifyCallback (MonoBtlsVerifyCallback callback)
		{
			CheckThrow ();

			verifyCallback = callback;
			mono_btls_ssl_ctx_set_cert_verify_callback (Handle.DangerousGetHandle (), verifyFuncPtr);
		}

		public void SetMinVersion (int version)
		{
			CheckThrow ();
			mono_btls_ssl_ctx_set_min_version (Handle.DangerousGetHandle (), version);
		}

		public void SetMaxVersion (int version)
		{
			CheckThrow ();
			mono_btls_ssl_ctx_set_max_version (Handle.DangerousGetHandle (), version);
		}

		public bool IsCipherSupported (short value)
		{
			CheckThrow ();
			return mono_btls_ssl_ctx_is_cipher_supported (Handle.DangerousGetHandle (), value) != 0;
		}

		public void SetCiphers (short[] ciphers, bool allow_unsupported)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (ciphers.Length * 2);
			try {
				Marshal.Copy (ciphers, 0, data, ciphers.Length);
				var ret = mono_btls_ssl_ctx_set_ciphers (
					Handle.DangerousGetHandle (),
					ciphers.Length, data, allow_unsupported ? 1 : 0);
				CheckError (ret > 0);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		protected override void Close ()
		{
			if (store != null) {
				store.Dispose ();
				store = null;
			}
			base.Close ();
		}
	}
}
#endif
