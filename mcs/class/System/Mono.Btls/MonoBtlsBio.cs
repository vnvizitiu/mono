//
// MonoBtlsBio.cs
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
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#if MONOTOUCH
using MonoTouch;
#endif

namespace Mono.Btls
{
	class MonoBtlsBio : MonoBtlsObject
	{
		internal MonoBtlsBio (BoringBioHandle handle)
			: base (handle)
		{
		}

		new protected internal BoringBioHandle Handle {
			get { return (BoringBioHandle)base.Handle; }
		}

		protected internal class BoringBioHandle : MonoBtlsHandle
		{
			public BoringBioHandle (IntPtr handle)
				: base (handle, true)
			{
			}

			protected override bool ReleaseHandle ()
			{
				if (handle != IntPtr.Zero) {
					mono_btls_bio_free (handle);
					handle = IntPtr.Zero;
				}
				return true;
			}

		}

		public static MonoBtlsBio CreateMonoStream (Stream stream)
		{
			return MonoBtlsBioMono.CreateStream (stream, false);
		}

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_read (IntPtr bio, IntPtr data, int len);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_write (IntPtr bio, IntPtr data, int len);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_flush (IntPtr bio);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_indent (IntPtr bio, uint indent, uint max_indent);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_hexdump (IntPtr bio, IntPtr data, int len, uint indent);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_bio_print_errors (IntPtr bio);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_bio_free (IntPtr handle);

		public int Read (byte[] buffer, int offset, int size)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				var ret = mono_btls_bio_read (Handle.DangerousGetHandle (), data, size);
				if (ret > 0)
					Marshal.Copy (data, buffer,offset, ret);
				return ret;
			} finally {
				if (release)
					Handle.DangerousRelease ();
				Marshal.FreeHGlobal (data);
			}
		}

		public int Write (byte[] buffer, int offset, int size)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				Marshal.Copy (buffer, offset, data, size);
				return mono_btls_bio_write (Handle.DangerousGetHandle (), data, size);
			} finally {
				if (release)
					Handle.DangerousRelease ();
				Marshal.FreeHGlobal (data);
			}
		}

		public int Flush ()
		{
			CheckThrow ();
			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				return mono_btls_bio_flush (Handle.DangerousGetHandle ());
			} finally {
				if (release)
					Handle.DangerousRelease ();
			}
		}

		public int Indent (uint indent, uint max_indent)
		{
			CheckThrow ();
			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				return mono_btls_bio_indent (Handle.DangerousGetHandle (), indent, max_indent);
			} finally {
				if (release)
					Handle.DangerousRelease ();
			}
		}

		public int HexDump (byte[] buffer, uint indent)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (buffer.Length);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				Marshal.Copy (buffer, 0, data, buffer.Length);
				return mono_btls_bio_hexdump (Handle.DangerousGetHandle (), data, buffer.Length, indent);
			} finally {
				if (release)
					Handle.DangerousRelease ();
				Marshal.FreeHGlobal (data);
			}
		}

		public void PrintErrors ()
		{
			CheckThrow ();
			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				mono_btls_bio_print_errors (Handle.DangerousGetHandle ());
			} finally {
				if (release)
					Handle.DangerousRelease ();
			}
		}
	}

	class MonoBtlsBioMemory : MonoBtlsBio
	{
		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_bio_mem_new ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static int mono_btls_bio_mem_get_data (IntPtr handle, out IntPtr data);

		public MonoBtlsBioMemory ()
			: base (new BoringBioHandle (mono_btls_bio_mem_new ()))
		{
		}

		public byte[] GetData ()
		{
			IntPtr data;
			bool release = false;
			try {
				Handle.DangerousAddRef (ref release);
				var size = mono_btls_bio_mem_get_data (Handle.DangerousGetHandle (), out data);
				CheckError (size > 0);
				var buffer = new byte[size];
				Marshal.Copy (data, buffer, 0, size);
				return buffer;
			} finally {
				if (release)
					Handle.DangerousRelease ();
			}
		}
	}

	interface IMonoBtlsBioMono
	{
		int Read (IntPtr data, int dataLength);

		int Write (IntPtr data, int dataLength);

		void Flush ();

		void Close ();
	}

	class MonoBtlsBioMono : MonoBtlsBio
	{
		GCHandle handle;
		IntPtr instance;
		BioIOFunc readFunc;
		BioIOFunc writeFunc;
		BioControlFunc controlFunc;
		IntPtr readFuncPtr;
		IntPtr writeFuncPtr;
		IntPtr controlFuncPtr;
		IMonoBtlsBioMono backend;

		public MonoBtlsBioMono (IMonoBtlsBioMono backend)
			: base (new BoringBioHandle (mono_btls_bio_mono_new ()))
		{
			this.backend = backend;
			handle = GCHandle.Alloc (this);
			instance = GCHandle.ToIntPtr (handle);
			readFunc = OnRead;
			writeFunc = OnWrite;
			controlFunc = Control;
			readFuncPtr = Marshal.GetFunctionPointerForDelegate (readFunc);
			writeFuncPtr = Marshal.GetFunctionPointerForDelegate (writeFunc);
			controlFuncPtr = Marshal.GetFunctionPointerForDelegate (controlFunc);
			mono_btls_bio_mono_initialize (Handle.DangerousGetHandle (), instance, readFuncPtr, writeFuncPtr, controlFuncPtr);
		}

		public static MonoBtlsBioMono CreateStream (Stream stream, bool ownsStream)
		{
			return new MonoBtlsBioMono (new StreamBackend (stream, ownsStream));
		}

		public static MonoBtlsBioMono CreateString (StringWriter writer)
		{
			return new MonoBtlsBioMono (new StringBackend (writer));
		}

		enum ControlCommand
		{
			Flush = 1
		}

		delegate int BioIOFunc (IntPtr bio, IntPtr data, int dataLength);
		delegate long BioControlFunc (IntPtr bio, ControlCommand command, long arg);

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static IntPtr mono_btls_bio_mono_new ();

		[MethodImpl (MethodImplOptions.InternalCall)]
		extern static void mono_btls_bio_mono_initialize (IntPtr handle, IntPtr instance, IntPtr readFunc, IntPtr writeFunc, IntPtr controlFunc);

		long Control (ControlCommand command, long arg)
		{
			Console.Error.WriteLine ("CONTROL: {0} {1:x}", command, arg);
			switch (command) {
			case ControlCommand.Flush:
				backend.Flush ();
				return 1;

			default:
				throw new NotImplementedException ();
			}
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (BioIOFunc))]
#endif
		static int OnRead (IntPtr instance, IntPtr data, int dataLength)
		{
			var c = (MonoBtlsBioMono)GCHandle.FromIntPtr (instance).Target;
			try {
				return c.backend.Read (data, dataLength);
			} catch (Exception ex) {
				c.SetException (ex);
				return -1;
			}
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (BioIOFunc))]
#endif
		static int OnWrite (IntPtr instance, IntPtr data, int dataLength)
		{
			var c = (MonoBtlsBioMono)GCHandle.FromIntPtr (instance).Target;
			try {
				return c.backend.Write (data, dataLength);
			} catch (Exception ex) {
				c.SetException (ex);
				return -1;
			}
		}

#if MONOTOUCH
		[MonoPInvokeCallback (typeof (BioControlFunc))]
#endif
		static long Control (IntPtr instance, ControlCommand command, long arg)
		{
			var c = (MonoBtlsBioMono)GCHandle.FromIntPtr (instance).Target;
			try {
				return c.Control (command, arg);
			} catch (Exception ex) {
				c.SetException (ex);
				return -1;
			}
		}

		protected override void Close ()
		{
			try {
				if (backend != null) {
					backend.Close ();
					backend = null;
				}
				if (handle.IsAllocated)
					handle.Free ();
			} finally {
				base.Close ();
			}
		}

		class StreamBackend : IMonoBtlsBioMono
		{
			Stream stream;
			bool ownsStream;

			public Stream InnerStream {
				get { return stream; }
			}

			public StreamBackend (Stream stream, bool ownsStream)
			{
				this.stream = stream;
				this.ownsStream = ownsStream;
			}

			public int Read (IntPtr data, int dataLength)
			{
				var buffer = new byte[dataLength];
				var ret = stream.Read (buffer, 0, dataLength);
				if (ret <= 0)
					return ret;
				Marshal.Copy (buffer, 0, data, ret);
				return ret;
			}

			public int Write (IntPtr data, int dataLength)
			{
				var buffer = new byte[dataLength];
				Marshal.Copy (data, buffer, 0, dataLength);
				stream.Write (buffer, 0, dataLength);
				return dataLength;
			}

			public void Flush ()
			{
				stream.Flush ();
			}

			public void Close ()
			{
				if (ownsStream && stream != null)
					stream.Dispose ();
				stream = null;
			}
		}

		class StringBackend : IMonoBtlsBioMono
		{
			StringWriter writer;
			Encoding encoding = new UTF8Encoding ();

			public StringBackend (StringWriter writer)
			{
				this.writer = writer;
			}

			public int Read (IntPtr data, int dataLength)
			{
				return -1;
			}
			public unsafe int Write (IntPtr data, int dataLength)
			{
				var text = encoding.GetString ((byte*)data.ToPointer (), dataLength);
				writer.Write (text);
				return dataLength;
			}
			public void Flush ()
			{
			}
			public void Close ()
			{
			}
		}
	}
}
#endif
