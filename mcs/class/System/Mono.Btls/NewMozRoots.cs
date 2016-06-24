//
// NewMozRoots.cs
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
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Mono.Btls
{
	static class NewMozRoots
	{
		private const string defaultUrl = "http://mxr.mozilla.org/seamonkey/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";

		static byte [] DecodeOctalString (string s)
		{
			string [] pieces = s.Split ('\\');
			byte [] data = new byte [pieces.Length - 1];
			for (int i = 1; i < pieces.Length; i++) {
				data [i - 1] = (byte)((pieces [i] [0] - '0' << 6) + (pieces [i] [1] - '0' << 3) + (pieces [i] [2] - '0'));
			}
			return data;
		}

		static MonoBtlsX509 DecodeCertificate (string s)
		{
			var rawdata = DecodeOctalString (s);
			return MonoBtlsX509.LoadFromData (rawdata, MonoBtlsX509Format.DER);
		}

		static Stream GetFile ()
		{
			var req = (HttpWebRequest)WebRequest.Create (defaultUrl);
			req.Timeout = 10000;
			return req.GetResponse ().GetResponseStream ();
		}

		public static List<MonoBtlsX509> DecodeCollection ()
		{
			var roots = new List<MonoBtlsX509> ();
			StringBuilder sb = new StringBuilder ();
			bool processing = false;

			using (Stream s = GetFile ()) {
				StreamReader sr = new StreamReader (s);
				while (true) {
					string line = sr.ReadLine ();
					if (line == null)
						break;

					if (processing) {
						if (line.StartsWith ("END")) {
							processing = false;
							var root = DecodeCertificate (sb.ToString ());
							roots.Add (root);

							sb = new StringBuilder ();
							continue;
						}
						sb.Append (line);
					} else {
						processing = line.StartsWith ("CKA_VALUE MULTILINE_OCTAL");
					}
				}
				return roots;
			}
		}

		static void WriteCertificate (MonoBtlsX509 x509, string filename)
		{
			using (var write = new FileStream (filename, FileMode.CreateNew)) {
				var data = x509.GetRawData ();
				write.Write (data, 0, data.Length);
			}
		}

		public static void Run (string directory)
		{
			var roots = DecodeCollection ();
			foreach (var x509 in roots) {
				long hash;
				using (var subject = x509.GetSubjectName ())
					hash = subject.GetHash ();
				var path = string.Format ("{0}/{1:x}.0", directory, hash);
				Console.WriteLine ("PATH: {0}", path);
				WriteCertificate (x509, path);
			}
			for (int i = 0; i < roots.Count; i++)
				roots [i].Dispose ();
		}
	}
}
#endif
