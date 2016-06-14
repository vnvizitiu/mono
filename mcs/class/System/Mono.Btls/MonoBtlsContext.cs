//
// MonoBtlsContext.cs
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
#if MONO_SECURITY_ALIAS
extern alias MonoSecurity;
#endif

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Runtime.InteropServices;

#if MONO_SECURITY_ALIAS
using MonoSecurity::Mono.Security.Interface;
#else
using Mono.Security.Interface;
#endif

using MNS = Mono.Net.Security;

namespace Mono.Btls
{
	class MonoBtlsContext : MNS.MobileTlsContext, IMonoBtlsBioMono
	{
		Stream innerStream;
		bool serverMode;
		string targetHost;
		SslProtocols enabledProtocols;
		X509Certificate serverCertificate;
		X509CertificateImplBtls nativeServerCertificate;
		MonoBtlsSslCtx ctx;
		MonoBtlsSsl ssl;
		MonoBtlsBio bio;
		MonoBtlsBio errbio;

		ICertificateValidator2 certificateValidator;
		MonoTlsConnectionInfo connectionInfo;
		bool isAuthenticated;
		bool connected;

		public MonoBtlsContext (
			MNS.MobileAuthenticatedStream parent, Stream innerStream,
			bool serverMode, string targetHost,
			SslProtocols enabledProtocols, X509Certificate serverCertificate,
			X509CertificateCollection clientCertificates, bool askForClientCert)
			: base (parent)
		{
			this.innerStream = innerStream;
			this.serverMode = serverMode;
			this.targetHost = targetHost;
			this.enabledProtocols = enabledProtocols;
			this.serverCertificate = serverCertificate;

			if (serverMode)
				nativeServerCertificate = GetServerCertificate (serverCertificate);

			certificateValidator = CertificateValidationHelper.GetDefaultValidator (Settings, Provider);
		}

		static X509CertificateImplBtls GetServerCertificate (X509Certificate certificate)
		{
			var impl = certificate.Impl as X509CertificateImplBtls;
			if (impl != null)
				return (X509CertificateImplBtls)impl.Clone ();

			var password = Guid.NewGuid ().ToString ();
			var buffer = certificate.Export (X509ContentType.Pfx, password);

			using (var pkcs12 = new MonoBtlsPkcs12 ()) {
				pkcs12.Import (buffer, password);

				using (var x509 = pkcs12.GetCertificate (0))
				using (var key = pkcs12.GetPrivateKey ())
					impl = new X509CertificateImplBtls (x509, key, true);

				return impl;
			}
		}

		new public MonoBtlsProvider Provider {
			get { return (MonoBtlsProvider)base.Provider; }
		}

		int VerifyCallback (MonoBtlsX509StoreCtx storeCtx)
		{
			using (var chainImpl = new X509ChainImplBtls (storeCtx))
			using (var managedChain = new X509Chain (chainImpl)) {
				var leaf = managedChain.ChainElements[0].Certificate;
				var result = certificateValidator.ValidateCertificate (targetHost, serverMode, leaf, managedChain);
				// ValidationResult ValidateCertificate (string targetHost, bool serverMode, X509CertificateCollection certificates);
				Console.WriteLine ("VERIFY CALLBACK DONE: {0}", result);
				if (result != null && result.Trusted && !result.UserDenied)
					return 1;
			}

			return 0;
		}

		#region implemented abstract members of MobileTlsStream
		public override void StartHandshake ()
		{
			InitializeConnection ();

			ssl = new MonoBtlsSsl (ctx);

			bio = new MonoBtlsBioMono (this);
			ssl.SetBio (bio);

			if (serverMode) {
				ssl.SetCertificate (nativeServerCertificate.X509);
				ssl.SetPrivateKey (nativeServerCertificate.NativePrivateKey);
			}
		}

		public override bool ProcessHandshake ()
		{
			var done = false;
			while (!done) {
				Debug ("ProcessHandshake");
				var status = DoProcessHandshake ();
				Debug ("ProcessHandshake #1: {0}", status);

				switch (status) {
				case MonoBtlsSslError.None:
					if (connected)
						done = true;
					else
						connected = true;
					break;
				case MonoBtlsSslError.WantRead:
				case MonoBtlsSslError.WantWrite:
					return false;
				default:
					throw new MonoBtlsException (status);
				}
			}

			ssl.PrintErrors ();

			return true;
		}

		MonoBtlsSslError DoProcessHandshake ()
		{
			if (connected)
				return ssl.Handshake ();
			else if (serverMode)
				return ssl.Accept ();
			else
				return ssl.Connect ();
		}

		public override void FinishHandshake ()
		{
			InitializeSession ();

			isAuthenticated = true;
		}

		void InitializeConnection ()
		{
			ctx = new MonoBtlsSslCtx ();
			errbio = MonoBtlsBio.CreateMonoStream (Console.OpenStandardError ());
			ctx.SetDebugBio (errbio);

			ctx.CertificateStore.LoadLocations (null, MonoBtlsProvider.GetSystemStoreLocation ());
			ctx.CertificateStore.SetDefaultPaths ();

			ctx.SetVerifyCallback (VerifyCallback);

			int minProtocol, maxProtocol;
			if ((enabledProtocols & SslProtocols.Tls) != 0)
				minProtocol = (int)TlsProtocolCode.Tls10;
			else if ((enabledProtocols & SslProtocols.Tls11) != 0)
				minProtocol = (int)TlsProtocolCode.Tls11;
			else
				minProtocol = (int)TlsProtocolCode.Tls12;

			if ((enabledProtocols & SslProtocols.Tls12) != 0)
				maxProtocol = (int)TlsProtocolCode.Tls12;
			else if ((enabledProtocols & SslProtocols.Tls11) != 0)
				maxProtocol = (int)TlsProtocolCode.Tls11;
			else
				maxProtocol = (int)TlsProtocolCode.Tls10;

			ctx.SetMinVersion (minProtocol);
			ctx.SetMaxVersion (maxProtocol);

			if (Settings != null && Settings.EnabledCiphers != null) {
				var ciphers = new short [Settings.EnabledCiphers.Length];
				for (int i = 0; i < ciphers.Length; i++)
					ciphers [i] = (short)Settings.EnabledCiphers [i];
				ctx.SetCiphers (ciphers, true);
			}
		}

		void InitializeSession ()
		{
			var cipher = (CipherSuiteCode)ssl.GetCipher ();
			var protocol = (TlsProtocolCode)ssl.GetVersion ();
			Debug ("GET CONNECTION INFO: {0:x}:{0} {1:x}:{1} {2}", cipher, protocol, (TlsProtocolCode)protocol);

			connectionInfo = new MonoTlsConnectionInfo {
				CipherSuiteCode = cipher,
				ProtocolVersion = GetProtocol (protocol)
			};
		}

		static TlsProtocols GetProtocol (TlsProtocolCode protocol)
		{
			switch (protocol) {
			case TlsProtocolCode.Tls10:
				return TlsProtocols.Tls10;
			case TlsProtocolCode.Tls11:
				return TlsProtocols.Tls11;
			case TlsProtocolCode.Tls12:
				return TlsProtocols.Tls12;
			default:
				throw new NotSupportedException ();
			}
		}

		public override void Flush ()
		{
			throw new NotImplementedException ();
		}

		public override int Read (byte[] buffer, int offset, int size, out bool wantMore)
		{
			Debug ("Read: {0} {1} {2}", buffer.Length, offset, size);

			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				var status = ssl.Read (data, ref size);
				Debug ("Read done: {0} {1}", status, size);

				if (status == MonoBtlsSslError.WantRead) {
					wantMore = true;
					return 0;
				} else if (status != MonoBtlsSslError.None) {
					throw new MonoBtlsException (status);
				}

				if (size > 0)
					Marshal.Copy (data, buffer, offset, size);

				wantMore = false;
				return size;
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public override int Write (byte[] buffer, int offset, int size, out bool wantMore)
		{
			Debug ("Write: {0} {1} {2}", buffer.Length, offset, size);

			var data = Marshal.AllocHGlobal (size);
			if (data == IntPtr.Zero)
				throw new OutOfMemoryException ();

			try {
				Marshal.Copy (buffer, offset, data, size);
				var status = ssl.Write (data, ref size);
				Debug ("Write done: {0} {1}", status, size);

				if (status == MonoBtlsSslError.WantWrite) {
					wantMore = true;
					return 0;
				} else if (status != MonoBtlsSslError.None) {
					throw new MonoBtlsException (status);
				}

				wantMore = false;
				return size;
			} finally {
				Marshal.FreeHGlobal (data);
			}
		}

		public override void Close ()
		{
			Debug ("Close!");
			ssl.Dispose ();
		}

		int IMonoBtlsBioMono.Read (byte[] buffer, int offset, int size, out bool wantMore)
		{
			Debug ("InternalRead: {0} {1}", offset, size);
			var ret = Parent.InternalRead (buffer, offset, size, out wantMore);
			Debug ("InternalReadDone: {0} {1}", ret, wantMore);
			return ret;
		}

		bool IMonoBtlsBioMono.Write (byte[] buffer, int offset, int size)
		{
			Debug ("InternalWrite: {0} {1}", offset, size);
			var ret = Parent.InternalWrite (buffer, offset, size);
			Debug ("InternalWrite done: {0}", ret);
			return ret;
		}

		void IMonoBtlsBioMono.Flush ()
		{
			;
		}

		void IMonoBtlsBioMono.Close ()
		{
			;
		}

		public override bool HasContext {
			get { return ssl != null && ssl.IsValid; }
		}
		public override bool IsAuthenticated {
			get { return isAuthenticated; }
		}
		public override bool IsServer {
			get { return serverMode; }
		}
		public override MonoTlsConnectionInfo ConnectionInfo {
			get { return connectionInfo; }
		}
		internal override X509Certificate LocalServerCertificate {
			get {
				throw new NotImplementedException ();
			}
		}
		internal override bool IsRemoteCertificateAvailable {
			get {
				throw new NotImplementedException ();
			}
		}
		internal override X509Certificate LocalClientCertificate {
			get { return null; }
		}
		public override X509Certificate RemoteCertificate {
			get {
				throw new NotImplementedException ();
			}
		}
		public override TlsProtocols NegotiatedProtocol {
			get { return connectionInfo.ProtocolVersion; }
		}
		#endregion
	}
}
#endif
