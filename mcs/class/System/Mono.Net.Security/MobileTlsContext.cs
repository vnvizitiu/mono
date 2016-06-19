//
// MobileTlsContext.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//

#if SECURITY_DEP
#if MONO_SECURITY_ALIAS
extern alias MonoSecurity;
#endif

#if MONO_SECURITY_ALIAS
using MonoSecurity::Mono.Security.Interface;
#else
using Mono.Security.Interface;
#endif

using System;
using System.IO;
using SD = System.Diagnostics;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace Mono.Net.Security
{
	abstract class MobileTlsContext : IDisposable
	{
		MobileAuthenticatedStream parent;

		public MobileTlsContext (MobileAuthenticatedStream parent)
		{
			this.parent = parent;
		}

		internal MobileAuthenticatedStream Parent {
			get { return parent; }
		}

		public MonoTlsSettings Settings {
			get { return parent.Settings; }
		}

		public MonoTlsProvider Provider {
			get { return parent.Provider; }
		}

		[SD.Conditional ("MARTIN_DEBUG")]
		protected void Debug (string message, params object[] args)
		{
			Console.Error.WriteLine ("{0}: {1}", GetType ().Name, string.Format (message, args));
		}

		public abstract bool HasContext {
			get;
		}

		public abstract bool IsAuthenticated {
			get;
		}

		public abstract bool IsServer {
			get;
		}

		public abstract void StartHandshake ();

		public abstract bool ProcessHandshake ();

		public abstract void FinishHandshake ();

		public abstract MonoTlsConnectionInfo ConnectionInfo {
			get;
		}

		internal abstract X509Certificate LocalServerCertificate {
			get;
		}

		internal abstract bool IsRemoteCertificateAvailable {
			get;
		}

		internal abstract X509Certificate LocalClientCertificate {
			get;
		}

		public abstract X509Certificate RemoteCertificate {
			get;
		}

		public abstract TlsProtocols NegotiatedProtocol {
			get;
		}

		public abstract void Flush ();

		public abstract int Read (byte[] buffer, int offset, int count, out bool wantMore);

		public abstract int Write (byte[] buffer, int offset, int count, out bool wantMore);

		public abstract void Close ();

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

		protected virtual void Dispose (bool disposing)
		{
		}

		~MobileTlsContext ()
		{
			Dispose (false);
		}
	}
}

#endif
