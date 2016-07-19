// Copyright 2015 Xamarin Inc. All rights reserved.

using System;
using MSI = Mono.Security.Interface;
using Mono.Btls;

namespace Mono.Net.Security
{
	static partial class MonoTlsProviderFactory
	{
		static IMonoTlsProvider CreateDefaultProvider ()
		{
#if SECURITY_DEP
			MSI.MonoTlsProvider provider = null;
#if MONODROID
			provider = GetDefaultTlsProvider_Android ();
#else
			if (MSI.MonoTlsProviderFactory._PrivateFactoryDelegate != null)
				provider = MSI.MonoTlsProviderFactory._PrivateFactoryDelegate ();
#endif
			if (provider != null)
				return new Private.MonoTlsProviderWrapper (provider);
#endif
			return null;
		}

#if SECURITY_DEP && MONODROID
		static MSI.MonoTlsProvider GetDefaultTlsProvider_Android ()
		{
			var provider = Environment.GetEnvironmentVariable ("XA_TLS_PROVIDER");
			switch (provider) {
			case null:
			case "default":
			case "legacy":
				return new Private.MonoDefaultTlsProvider ();
			case "btls":
				if (!MonoBtlsProvider.IsSupported ())
					throw new NotSupportedException ("BTLS in not supported!");
				return new MonoBtlsProvider ();
			default:
				throw new NotSupportedException (string.Format ("Invalid TLS Provider: `{0}'.", provider));
			}
		}
#endif
	}
}
