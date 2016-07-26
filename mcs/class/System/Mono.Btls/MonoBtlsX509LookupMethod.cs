//
// MonoBtlsX509LookupMethod.cs
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
	class MonoBtlsX509LookupMethod : MonoBtlsObject
	{
		internal class BoringX509LookupMethodHandle : MonoBtlsHandle
		{
			public BoringX509LookupMethodHandle (IntPtr handle)
				: base (handle, true)
			{
			}

			protected override bool ReleaseHandle ()
			{
				mono_btls_x509_lookup_method_free (handle);
				return true;
			}
		}

		new internal BoringX509LookupMethodHandle Handle {
			get { return (BoringX509LookupMethodHandle)base.Handle; }
		}

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_x509_lookup_method_by_file ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_x509_lookup_method_by_hash_dir ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_x509_lookup_method_free (IntPtr handle);

		internal MonoBtlsX509LookupMethod (BoringX509LookupMethodHandle handle)
			: base (handle)
		{
		}

		public static MonoBtlsX509LookupMethod ByFile ()
		{
			var handle = mono_btls_x509_lookup_method_by_file ();
			if (handle == IntPtr.Zero)
				return null;
			return new MonoBtlsX509LookupMethod (new BoringX509LookupMethodHandle (handle));
		}

		public static MonoBtlsX509LookupMethod ByHashDir ()
		{
			var handle = mono_btls_x509_lookup_method_by_hash_dir ();
			if (handle == IntPtr.Zero)
				return null;
			return new MonoBtlsX509LookupMethod (new BoringX509LookupMethodHandle (handle));
		}
	}

	delegate MonoBtlsX509 MonoBtlsX509LookupBySubjectFunc (MonoBtlsX509Name name);

	internal class MonoBtlsX509LookupMethodMono : MonoBtlsX509LookupMethod
	{
		delegate int NewItemFunc (IntPtr instance);
		delegate int InitFunc (IntPtr instance);
		delegate int ShutdownFunc (IntPtr instance);
		delegate int BySubjectFunc (IntPtr instance, IntPtr name, out IntPtr x509_ptr);
#if FIXME
		delegate int ByFingerPrintFunc (IntPtr instance, IntPtr bytes, int len, out IntPtr x509_ptr);
#endif

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_x509_lookup_method_mono_new ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_x509_lookup_method_mono_set_by_subject_func (
			IntPtr handle, IntPtr by_subject_func);

#if FIXME
		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_x509_lookup_method_mono_set_by_fingerprint_func (
			IntPtr handle, IntPtr by_fingerprint_func);
#endif

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_x509_lookup_method_mono_init (
			IntPtr handle, IntPtr instance,
			IntPtr new_item_func, IntPtr init_func, IntPtr shutdown_func);

		MonoBtlsX509LookupBySubjectFunc callback;

		GCHandle handle;
		IntPtr instance;
		InitFunc initFunc;
		NewItemFunc newItemFunc;
		ShutdownFunc shutdownFunc;
		BySubjectFunc bySubjectFunc;
#if FIXME
		ByFingerPrintFunc byFingerPrintFunc;
#endif
		IntPtr initFuncPtr;
		IntPtr newItemFuncPtr;
		IntPtr shutdownFuncPtr;
		IntPtr bySubjectFuncPtr;
#if FIXME
		IntPtr byFingerPrintFuncPtr;
#endif

		internal MonoBtlsX509LookupMethodMono (MonoBtlsX509LookupBySubjectFunc callback)
			: base (new BoringX509LookupMethodHandle (mono_btls_x509_lookup_method_mono_new ()))
		{
			this.callback = callback;

			handle = GCHandle.Alloc (this);
			instance = GCHandle.ToIntPtr (handle);
			initFunc = OnInit;
			newItemFunc = OnNewItem;
			shutdownFunc = OnShutdown;
			bySubjectFunc = OnGetBySubject;
#if FIXME
			byFingerPrintFunc = OnGetByFingerPrint;
#endif
			initFuncPtr = Marshal.GetFunctionPointerForDelegate (initFunc);
			newItemFuncPtr = Marshal.GetFunctionPointerForDelegate (newItemFunc);
			shutdownFuncPtr = Marshal.GetFunctionPointerForDelegate (shutdownFunc);
			bySubjectFuncPtr = Marshal.GetFunctionPointerForDelegate (bySubjectFunc);
#if FIXME
			byFingerPrintFuncPtr = Marshal.GetFunctionPointerForDelegate (byFingerPrintFunc);
#endif
			mono_btls_x509_lookup_method_mono_init (
				Handle.DangerousGetHandle (), instance,
				newItemFuncPtr, initFuncPtr, shutdownFuncPtr);
			mono_btls_x509_lookup_method_mono_set_by_subject_func (
				Handle.DangerousGetHandle (), bySubjectFuncPtr);
#if FIXME
			mono_btls_x509_lookup_method_mono_set_by_fingerprint_func (
				Handle.DangerousGetHandle (), byFingerPrintFuncPtr);
#endif
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (InitFunc))]
#endif
		static int OnInit (IntPtr instance)
		{
			Console.WriteLine ("LOOKUP METHOD - ON INIT");
			return 1;
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (NewItemFunc))]
#endif
		static int OnNewItem (IntPtr instance)
		{
			Console.WriteLine ("LOOKUP METHOD - ON NEW ITEM");
			return 1;
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (ShutdownFunc))]
#endif
		static int OnShutdown (IntPtr instance)
		{
			Console.WriteLine ("LOOKUP METHOD - ON SHUTDOWN");
			return 1;
		}

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
					var x509 = obj.callback (name_obj);
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

#if FIXME
		public MonoBtlsX509 GetBySubject (MonoBtlsX509Name name)
		{
			Console.WriteLine ("GET BY SUBJECT: {0} {1:X}", name.GetString (), name.GetHash ());

			var hash = name.GetHashOld ().ToString ("x").ToLowerInvariant ();

			var root = MonoBtlsProvider.GetSystemStoreLocation ();
			var path = string.Format ("{0}/{1:x8}.0", root, hash);
			Console.WriteLine ("PATH: {0}:{1}", File.Exists (path), path);
			if (!File.Exists (path)) {
				Console.Error.WriteLine ("CERT NOT FOUND!");
				return null;
			}

			var bytes = File.ReadAllBytes (path);
			var x509 = MonoBtlsX509.LoadFromData (bytes, MonoBtlsX509Format.PEM);
			Console.WriteLine ("GOT X509: {0}", x509.GetSubjectNameString ());
			return x509;
		}
#endif

#if FIXME
#if MONOTOUCH
		[MonoPInvokeCallback (typeof (ByFingerPrintFunc))]
#endif
		static int OnGetByFingerPrint (IntPtr instance, IntPtr data_ptr, int len, out IntPtr x509_ptr)
		{
			try {
				var obj = (MonoBtlsX509LookupMethodMono)GCHandle.FromIntPtr (instance).Target;
				var fingerprint = new byte [len];
				Marshal.Copy (data_ptr, fingerprint, 0, len);
				var x509 = obj.GetByFingerPrint (fingerprint);
				if (x509 != null) {
					x509_ptr = x509.Handle.StealHandle ();
					return 1;
				} else {
					x509_ptr = IntPtr.Zero;
					return 0;
				}
			} catch (Exception ex) {
				Console.WriteLine ("LOOKUP METHOD - GET BY FINGERPRINT EX: {0}", ex);
				x509_ptr = IntPtr.Zero;
				return 0;
			}
		}

		MonoBtlsX509 GetByFingerPrint (byte [] fingerprint)
		{
			Console.WriteLine ("GET BY FINGERPRINT");
			// DebugHelper.WriteLine ("FINGERPRINT", fingerprint);
			// var x509 = MartinTest.GetCACertificate ().Copy ();
			// x509.Test ();
			// return x509;
			throw new NotImplementedException ();
		}
#endif

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
