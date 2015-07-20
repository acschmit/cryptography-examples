package org.albertschmitt.cryptography.examples;

import org.albertschmitt.cryptography.support.Support;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.albertschmitt.crypto.RSAService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;

/**
 * Example 010.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Check for existence of RSA Keys.</li>
 * <li>Generate RSA Keys.</li>
 * <li>Read RSA Keys.</li>
 * <li>Encrypt and Decrypt a data file using streams.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_010
{

	private static final String TESTDATA_DEC_FILE = "./Example_010.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_010.enc.txt";
	private static final String TESTDATA_FILE = "./Example_010.txt";
	private static final String privateKeyfile = "./Example_010_private_key.pem";
	private static final String publicKeyfile = "./Example_010_public_key.pem";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_010.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		/**
		 * Create a public / private RSA key pair.
		 */
		final RSAService rsa = new RSAService();
		if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
		{
			System.out.println("Begin Create RSA Keys.");
			rsa.generateKey(privateKeyfile, publicKeyfile);
			System.out.println("End Create RSA Keys.");
		}

		/**
		 * RSA keys are synchronous; both public and private keys are required
		 * to encrypt and decrypt a message. A client process would not have
		 * both keys, this is only for demonstration purposes.
		 */
		System.out.println("Begin Read RSA Keys.");
		RSAPrivateKey privateKey = rsa.readPrivateKey(privateKeyfile);
		RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
		System.out.println("End Read RSA Keys.");

		/**
		 * Use public key to encrypt a file stream directly to another file
		 * stream.
		 */
		System.out.println("Begin Encrypt Data.");
		try (FileOutputStream outstream = new FileOutputStream(TESTDATA_ENC_FILE);
			 FileInputStream instream = new FileInputStream(TESTDATA_FILE))
		{
			rsa.encode(instream, outstream, publicKey);
		}
		System.out.println("End Encrypt Data.");

		/**
		 * Now decrypt the encrypted file using the private key.
		 */
		System.out.println("Begin Decrypt Data.");
		try (FileOutputStream outstream = new FileOutputStream(TESTDATA_DEC_FILE);
			 FileInputStream instream = new FileInputStream(TESTDATA_ENC_FILE))
		{
			rsa.decode(instream, outstream, privateKey);

		}
		System.out.println("End Decrypt Data.");

		/**
		 * Compare the original and decrypted files.
		 */
		try (FileInputStream is_original = new FileInputStream(TESTDATA_FILE);
			 FileInputStream is_decoded = new FileInputStream(TESTDATA_DEC_FILE))
		{
			String shaOriginal = DigestSHA.sha256(is_original);
			String shaDecoded = DigestSHA.sha256(is_decoded);

			if (Compare.safeEquals(shaOriginal.getBytes("UTF-8"), shaDecoded.getBytes("UTF-8")))
			{
				System.out.println("Encrypted and decrypted files are the same.");
			}
			else
			{
				System.out.println("Encrypted and decrypted files are NOT the same.");
			}
		}
		System.out.println("End Example_010a.");
	}
}
