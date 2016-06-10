//
// MonoBtlsX509StoreCtx.cs
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
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace Mono.Btls
{
	class MonoBtlsX509StoreCtx : MonoBtlsObject
	{
		internal class BoringX509StoreCtxHandle : MonoBtlsHandle
		{
			bool dontFree;

			internal BoringX509StoreCtxHandle ()
				: base ()
			{
			}

			internal BoringX509StoreCtxHandle (IntPtr handle)
				: base ()
			{
				base.handle = handle;
				this.dontFree = true;
			}

			protected override bool ReleaseHandle ()
			{
				if (!dontFree)
					mono_btls_x509_store_ctx_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_store_ctx_free (IntPtr handle);
		}

		int? verifyResult;

		new internal BoringX509StoreCtxHandle Handle {
			get { return (BoringX509StoreCtxHandle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringX509StoreCtxHandle mono_btls_x509_store_ctx_new ();

		[DllImport (DLL)]
		extern static BoringX509StoreCtxHandle mono_btls_x509_store_ctx_from_ptr (IntPtr ctx);

		[DllImport (DLL)]
		extern static MonoBtlsX509Error mono_btls_x509_store_ctx_get_error (BoringX509StoreCtxHandle handle, out IntPtr error_string);

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_ctx_get_error_depth (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509Chain.BoringX509ChainHandle mono_btls_x509_store_ctx_get_chain (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_ctx_init (BoringX509StoreCtxHandle handle,
		                                                     MonoBtlsX509Store.BoringX509StoreHandle store, MonoBtlsX509Chain.BoringX509ChainHandle chain);

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_ctx_set_param (BoringX509StoreCtxHandle handle, MonoBtlsX509VerifyParam.BoringX509VerifyParamHandle param);

		[DllImport (DLL)]
		extern static void mono_btls_x509_store_ctx_test (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static int mono_btls_x509_store_ctx_verify_cert (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_x509_store_ctx_get_by_subject (BoringX509StoreCtxHandle handle, MonoBtlsX509Name.BoringX509NameHandle name);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_x509_store_ctx_get_current_cert (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509.BoringX509Handle mono_btls_x509_store_ctx_get_current_issuer (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static MonoBtlsX509VerifyParam.BoringX509VerifyParamHandle mono_btls_x509_store_get_verify_param (BoringX509StoreCtxHandle handle);

		[DllImport (DLL)]
		extern static BoringX509StoreCtxHandle mono_btls_x509_store_ctx_up_ref (BoringX509StoreCtxHandle handle);

		internal MonoBtlsX509StoreCtx ()
			: base (mono_btls_x509_store_ctx_new ())
		{
		}

		internal MonoBtlsX509StoreCtx (int preverify_ok, IntPtr store_ctx)
			: base (mono_btls_x509_store_ctx_from_ptr (store_ctx))
		{
			verifyResult = preverify_ok;
		}

		internal MonoBtlsX509StoreCtx (BoringX509StoreCtxHandle ptr, int? verifyResult)
			: base (ptr)
		{
			this.verifyResult = verifyResult;
		}

		public MonoBtlsX509Error GetError ()
		{
			IntPtr error_string_ptr;
			return mono_btls_x509_store_ctx_get_error (Handle, out error_string_ptr);
		}

		public MonoBtlsX509Exception GetException ()
		{
			IntPtr error_string_ptr;
			var error = mono_btls_x509_store_ctx_get_error (Handle, out error_string_ptr);
			if (error == 0)
				return null;
			if (error_string_ptr != IntPtr.Zero) {
				var error_string = Marshal.PtrToStringAnsi (error_string_ptr);
				return new MonoBtlsX509Exception (error, error_string);
			}
			return new MonoBtlsX509Exception (error, "Unknown verify error.");
		}

		public MonoBtlsX509Chain GetChain ()
		{
			var chain = mono_btls_x509_store_ctx_get_chain (Handle);
			CheckError (chain != null);
			return new MonoBtlsX509Chain (chain);
		}

		public void Test ()
		{
			mono_btls_x509_store_ctx_test (Handle);
		}

		public void Initialize (MonoBtlsX509Store store, MonoBtlsX509Chain chain)
		{
			var ret = mono_btls_x509_store_ctx_init (Handle, store.Handle, chain.Handle);
			CheckError (ret);
		}

		public void SetVerifyParam (MonoBtlsX509VerifyParam param)
		{
			var ret = mono_btls_x509_store_ctx_set_param (Handle, param.Handle);
			CheckError (ret);
		}

		public int VerifyResult {
			get {
				if (verifyResult == null)
					throw new InvalidOperationException ();
				return verifyResult.value;
			}
		}

		public int Verify ()
		{
			verifyResult = mono_btls_x509_store_ctx_verify_cert (Handle);
			return verifyResult.Value;
		}

		public MonoBtlsX509 LookupBySubject (MonoBtlsX509Name name)
		{
			var handle = mono_btls_x509_store_ctx_get_by_subject (Handle, name.Handle);
			if (handle == null || handle.IsInvalid)
				return null;
			return new MonoBtlsX509 (handle);
		}

		public MonoBtlsX509 GetCurrentCertificate ()
		{
			var x509 = mono_btls_x509_store_ctx_get_current_cert (Handle);
			if (x509 == null || x509.IsInvalid)
				return null;
			return new MonoBtlsX509 (x509);
		}

		public MonoBtlsX509 GetCurrentIssuer ()
		{
			var x509 = mono_btls_x509_store_ctx_get_current_issuer (Handle);
			if (x509 == null || x509.IsInvalid)
				return null;
			return new MonoBtlsX509 (x509);
		}

		public MonoBtlsX509VerifyParam GetVerifyParam ()
		{
			var param = mono_btls_x509_store_get_verify_param (Handle);
			if (param == null || param.IsInvalid)
				return null;
			return new MonoBtlsX509VerifyParam (param);
		}

		public MonoBtlsX509StoreCtx Copy ()
		{
			var copy = mono_btls_x509_store_ctx_up_ref (Handle);
			CheckError (copy != null && !copy.IsInvalid);
			return new MonoBtlsX509StoreCtx (copy, verifyResult);
		}
	}
}

