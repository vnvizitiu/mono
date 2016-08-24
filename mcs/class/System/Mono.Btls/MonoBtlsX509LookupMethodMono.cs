//
// MonoBtlsX509LookupMethodMono.cs
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

#if MONOTOUCH
using MonoTouch;
#endif

namespace Mono.Btls
{
	internal abstract class MonoBtlsX509LookupMethodMono : MonoBtlsX509LookupMethod
	{
		delegate int BySubjectFunc (IntPtr instance, IntPtr name, out IntPtr x509_ptr);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_x509_lookup_method_mono_new ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_x509_lookup_method_mono_init (
			IntPtr handle, IntPtr instance, IntPtr by_subject_func);

		GCHandle handle;
		IntPtr instance;
		BySubjectFunc bySubjectFunc;
		IntPtr bySubjectFuncPtr;

		internal MonoBtlsX509LookupMethodMono ()
			: base (new BoringX509LookupMethodHandle (mono_btls_x509_lookup_method_mono_new ()))
		{
			handle = GCHandle.Alloc (this);
			instance = GCHandle.ToIntPtr (handle);
			bySubjectFunc = OnGetBySubject;
			bySubjectFuncPtr = Marshal.GetFunctionPointerForDelegate (bySubjectFunc);
			mono_btls_x509_lookup_method_mono_init (
				Handle.DangerousGetHandle (), instance, bySubjectFuncPtr);
		}

		protected abstract MonoBtlsX509 LookupBySubject (MonoBtlsX509Name name);

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (BySubjectFunc))]
#endif
		static int OnGetBySubject (IntPtr instance, IntPtr name_ptr, out IntPtr x509_ptr)
		{
			try {
				MonoBtlsX509LookupMethodMono obj;
				MonoBtlsX509Name.BoringX509NameHandle name_handle = null;
				try {
					obj = (MonoBtlsX509LookupMethodMono)GCHandle.FromIntPtr (instance).Target;
					name_handle = new MonoBtlsX509Name.BoringX509NameHandle (name_ptr, false);
					MonoBtlsX509Name name_obj = new MonoBtlsX509Name (name_handle);
					var x509 = obj.LookupBySubject (name_obj);
					if (x509 != null) {
						x509_ptr = x509.Handle.StealHandle ();
						return 1;
					} else {
						x509_ptr = IntPtr.Zero;
						return 0;
					}
				} finally {
					if (name_handle != null)
						name_handle.Dispose ();
				}
			} catch (Exception ex) {
				Console.WriteLine ("LOOKUP METHOD - GET BY SUBJECT EX: {0}", ex);
				x509_ptr = IntPtr.Zero;
				return 0;
			}
		}

		protected override void Close ()
		{
			try {
				if (handle.IsAllocated)
					handle.Free ();
			} finally {
				base.Close ();
			}
		}
	}
}
#endif
