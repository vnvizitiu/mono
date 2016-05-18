using System;
using System.Runtime.CompilerServices;

namespace System
{
	public static class MartinTest
	{
		[MethodImplAttribute (MethodImplOptions.InternalCall)]
		public extern static int Hello ();
	}
}
