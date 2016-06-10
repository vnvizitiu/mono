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
			protected override bool ReleaseHandle ()
			{
				mono_btls_x509_lookup_method_free (handle);
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_x509_lookup_method_free (IntPtr handle);
		}

		new internal BoringX509LookupMethodHandle Handle {
			get { return (BoringX509LookupMethodHandle)base.Handle; }
		}

		[DllImport (DLL)]
		extern static BoringX509LookupMethodHandle mono_btls_x509_lookup_method_by_file ();

		[DllImport (DLL)]
		extern static BoringX509LookupMethodHandle mono_btls_x509_lookup_method_by_hash_dir ();

		internal MonoBtlsX509LookupMethod (BoringX509LookupMethodHandle handle)
			: base (handle)
		{
		}

		public static MonoBtlsX509LookupMethod ByFile ()
		{
			return new MonoBtlsX509LookupMethod (mono_btls_x509_lookup_method_by_file ());
		}

		public static MonoBtlsX509LookupMethod ByHashDir ()
		{
			return new MonoBtlsX509LookupMethod (mono_btls_x509_lookup_method_by_hash_dir ());
		}
	}

	internal class MonoBtlsX509LookupMethodMono : MonoBtlsX509LookupMethod
	{
		delegate int NewItemFunc (IntPtr instance);
		delegate int InitFunc (IntPtr instance);
		delegate int ShutdownFunc (IntPtr instance);
		delegate int BySubjectFunc (IntPtr instance, IntPtr name, out IntPtr x509_ptr);
		delegate int ByFingerPrintFunc (IntPtr instance, IntPtr bytes, int len, out IntPtr x509_ptr);

		[DllImport (DLL)]
		extern static BoringX509LookupMethodHandle mono_btls_x509_lookup_method_new_mono ();

		[DllImport (DLL)]
		extern static void mono_btls_x509_lookup_method_mono_set_by_subject_func (
			BoringX509LookupMethodHandle handle, BySubjectFunc by_subject_func);

		[DllImport (DLL)]
		extern static void mono_btls_x509_lookup_method_mono_set_by_fingerprint_func (
			BoringX509LookupMethodHandle handle, ByFingerPrintFunc by_fingerprint_func);

		[DllImport (DLL)]
		extern static void mono_btls_x509_lookup_method_init_mono (
			BoringX509LookupMethodHandle handle, IntPtr instance,
			NewItemFunc new_item_func, InitFunc init_func, ShutdownFunc shutdown_func);

		GCHandle handle;
		IntPtr instance;
		InitFunc initFunc;
		NewItemFunc newItemFunc;
		ShutdownFunc shutdownFunc;
		BySubjectFunc bySubjectFunc;
		ByFingerPrintFunc byFingerPrintFunc;

		internal MonoBtlsX509LookupMethodMono ()
			: base (mono_btls_x509_lookup_method_new_mono ())
		{
			handle = GCHandle.Alloc (this);
			instance = GCHandle.ToIntPtr (handle);
			initFunc = OnInit;
			newItemFunc = OnNewItem;
			shutdownFunc = OnShutdown;
			bySubjectFunc = OnGetBySubject;
			byFingerPrintFunc = OnGetByFingerPrint;
			mono_btls_x509_lookup_method_init_mono (Handle, instance, newItemFunc, initFunc, shutdownFunc);
			mono_btls_x509_lookup_method_mono_set_by_subject_func (Handle, bySubjectFunc);
			mono_btls_x509_lookup_method_mono_set_by_fingerprint_func (Handle, byFingerPrintFunc);
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
					name_handle = new MonoBtlsX509Name.BoringX509NameHandle (name_ptr);
					MonoBtlsX509Name name_obj = new MonoBtlsX509Name (name_handle);
					var x509 = obj.GetBySubject (name_obj);
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
