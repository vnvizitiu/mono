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
			protected override bool ReleaseHandle ()
			{
				if (handle != IntPtr.Zero) {
					mono_btls_bio_free (handle);
					handle = IntPtr.Zero;
				}
				return true;
			}

			[DllImport (DLL)]
			extern static void mono_btls_bio_free (IntPtr handle);
		}

		public static MonoBtlsBio CreateMonoStream (Stream stream)
		{
			return new MonoBtlsBioMonoStream (stream, false);
		}

		[DllImport (DLL)]
		extern static int mono_btls_bio_read (BoringBioHandle bio, IntPtr data, int len);

		[DllImport (DLL)]
		extern static int mono_btls_bio_write (BoringBioHandle bio, IntPtr data, int len);

		[DllImport (DLL)]
		extern static int mono_btls_bio_flush (BoringBioHandle bio);

		[DllImport (DLL)]
		extern static int mono_btls_bio_indent (BoringBioHandle bio, uint indent, uint max_indent);

		[DllImport (DLL)]
		extern static int mono_btls_bio_hexdump (BoringBioHandle bio, IntPtr data, int len, uint indent);

		[DllImport (DLL)]
		extern static void mono_btls_bio_print_errors (BoringBioHandle bio);

		public int Read (byte[] buffer, int offset, int size)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				var ret = mono_btls_bio_read (Handle, data, size);
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
				return mono_btls_bio_write (Handle, data, size);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public int Flush ()
		{
			CheckThrow ();
			return mono_btls_bio_flush (Handle);
		}

		public int Indent (uint indent, uint max_indent)
		{
			CheckThrow ();
			return mono_btls_bio_indent (Handle, indent, max_indent);
		}

		public int HexDump (byte[] buffer, uint indent)
		{
			CheckThrow ();
			var data = Marshal.AllocHGlobal (buffer.Length);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				Marshal.Copy (buffer, 0, data, buffer.Length);
				return mono_btls_bio_hexdump (Handle, data, buffer.Length, indent);
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public void PrintErrors ()
		{
			CheckThrow ();
			mono_btls_bio_print_errors (Handle);
		}
	}

	class MonoBtlsBioMemory : MonoBtlsBio
	{
		[DllImport (DLL)]
		extern static BoringBioHandle mono_btls_bio_new_mem ();

		[DllImport (DLL)]
		extern static int mono_btls_bio_mem_get_data (BoringBioHandle handle, out IntPtr data);

		public MonoBtlsBioMemory ()
			: base (mono_btls_bio_new_mem ())
		{
		}

		public byte[] GetData ()
		{
			IntPtr data;
			var size = mono_btls_bio_mem_get_data (Handle, out data);
			CheckError (size > 0);
			var buffer = new byte [size];
			Marshal.Copy (data, buffer, 0, size);
			return buffer;
		}
	}

	abstract class MonoBtlsBioMono : MonoBtlsBio
	{
		GCHandle handle;
		IntPtr instance;
		BioIOFunc readFunc;
		BioIOFunc writeFunc;
		BioControlFunc controlFunc;

		public MonoBtlsBioMono ()
			: base (mono_btls_bio_new ())
		{
			handle = GCHandle.Alloc (this);
			instance = GCHandle.ToIntPtr (handle);
			readFunc = OnRead;
			writeFunc = OnWrite;
			controlFunc = Control;
			mono_btls_bio_initialize (Handle, instance, readFunc, writeFunc, controlFunc);
		}

		enum ControlCommand {
			Flush = 1
		}

		delegate int BioIOFunc (IntPtr bio, IntPtr data, int dataLength);
		delegate long BioControlFunc (IntPtr bio, ControlCommand command, long arg);

		[DllImport (DLL)]
		extern static BoringBioHandle mono_btls_bio_new ();

		[DllImport (DLL)]
		extern static void mono_btls_bio_initialize (BoringBioHandle handle, IntPtr instance, BioIOFunc readFunc, BioIOFunc writeFunc, BioControlFunc controlFunc);

		protected abstract int OnRead (IntPtr data, int dataLength);

		protected abstract int OnWrite (IntPtr data, int dataLength);

		protected abstract void OnFlush ();

		long Control (ControlCommand command, long arg)
		{
			Console.Error.WriteLine ("CONTROL: {0} {1:x}", command, arg);
			switch (command) {
			case ControlCommand.Flush:
				OnFlush ();
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
				return c.OnRead (data, dataLength);
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
				return c.OnWrite (data, dataLength);
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
				if (handle.IsAllocated)
					handle.Free ();
			} finally {
				base.Close ();
			}
		}
	}

	class MonoBtlsBioMonoStream : MonoBtlsBioMono
	{
		Stream stream;
		bool ownsStream;

		public Stream InnerStream {
			get { return stream; }
		}

		public MonoBtlsBioMonoStream (Stream stream, bool ownsStream)
		{
			this.stream = stream;
			this.ownsStream = ownsStream;
		}

		protected override int OnRead (IntPtr data, int dataLength)
		{
			var buffer = new byte [dataLength];
			var ret = stream.Read (buffer, 0, dataLength);
			if (ret <= 0)
				return ret;
			Marshal.Copy (buffer, 0, data, ret);
			return ret;
		}

		protected override int OnWrite (IntPtr data, int dataLength)
		{
			var buffer = new byte [dataLength];
			Marshal.Copy (data, buffer, 0, dataLength);
			stream.Write (buffer, 0, dataLength);
			return dataLength;
		}

		protected override void OnFlush ()
		{
			stream.Flush ();
		}

		protected override void Close ()
		{
			try {
				if (ownsStream && stream != null)
					stream.Dispose ();
				stream = null;
			} finally {
				base.Close ();
			}
		}
	}

	class MonoBtlsBioMonoString : MonoBtlsBioMono
	{
		StringWriter writer = new StringWriter ();
		Encoding encoding = new UTF8Encoding ();

		protected override int OnRead (IntPtr data, int dataLength)
		{
			return -1;
		}
		protected unsafe override int OnWrite (IntPtr data, int dataLength)
		{
			var text = encoding.GetString ((byte*)data.ToPointer (), dataLength);
			writer.Write (text);
			return dataLength;
		}
		protected override void OnFlush ()
		{
			;
		}

		public string GetText ()
		{
			return writer.ToString ();
		}
	}
}
#endif
