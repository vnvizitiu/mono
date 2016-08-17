using System;
using System.IO;
using System.Text;

namespace Mono.Btls
{
	static class BtlsCertSync
	{
		static void Main (string[] args)
		{
			if (!MonoBtlsProvider.IsSupported ()) {
				Console.Error.WriteLine ("BTLS is not supported in this runtime!");
				Environment.Exit (255);
			}

			var configPath = Environment.GetFolderPath (Environment.SpecialFolder.ApplicationData);
			configPath = Path.Combine (configPath, ".mono");

			var oldStorePath = Path.Combine (configPath, "certs", "Trust");
			var newStorePath = Path.Combine (configPath, "btls-certs");

			if (!Directory.Exists (oldStorePath)) {
				Console.WriteLine ("Old trust store {0} does not exist.");
				Environment.Exit (255);
			}

			if (Directory.Exists (newStorePath)) {
				Directory.Delete (newStorePath, true);
				Directory.CreateDirectory (newStorePath);
			}

			var oldfiles = Directory.GetFiles (oldStorePath, "*.cer");
			Console.WriteLine ("Found {0} files in the old store.", oldfiles.Length);

			foreach (var file in oldfiles) {
				Console.WriteLine ("Converting {0}.", file);
				var data = File.ReadAllBytes (file);
				using (var x509 = MonoBtlsX509.LoadFromData (data, MonoBtlsX509Format.DER)) {
					ConvertToNewFormat (newStorePath, x509);
				}
			}
		}

		static void ConvertToNewFormat (string root, MonoBtlsX509 x509)
		{
			var subject = x509.GetSubjectName ();
			Console.WriteLine ("  certificate: {0}", subject.GetString ());

			var hash = subject.GetHash ();

			string newName;
			int index = 0;
			do {
				newName = Path.Combine (root, string.Format ("{0:x}.{1}", hash, index++));
			} while (File.Exists (newName));
			Console.WriteLine ("  new name: {0}", newName);

			Print (x509, newName);
		}

		static void Print (MonoBtlsX509 x509, string filename)
		{
			using (var stream = new FileStream (filename, FileMode.Create))
			using (var bio = MonoBtlsBio.CreateMonoStream (stream)) {
				x509.GetRawData (bio, MonoBtlsX509Format.PEM);
				x509.Print (bio);

				var hash = x509.GetCertHash ();
				var output = new StringBuilder ();
				output.Append ("SHA1 Fingerprint=");
				for (int i = 0; i < hash.Length; i++) {
					if (i > 0)
						output.Append (":");
					output.AppendFormat ("{0:X2}", hash [i]);
				}
				output.AppendLine ();
				var outputData = Encoding.ASCII.GetBytes (output.ToString ());
				bio.Write (outputData, 0, outputData.Length);
			}
		}
	}
}
