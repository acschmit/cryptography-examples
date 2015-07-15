package org.albertschmitt.cryptography.examples;

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
 * <li>Generate RSA Keys using FileOutputStream.</li>
 * <li>Read RSA Keys FileInputStream.</li>
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
			FileOutputStream os_private = new FileOutputStream(privateKeyfile);
			FileOutputStream os_public = new FileOutputStream(publicKeyfile);
			rsa.generateKey(os_private, os_public);
			System.out.println("End Create RSA Keys.");
		}

		/**
		 * RSA keys are asynchronous; there is a public and private key. Each
		 * key can only decrypt data encrypted with the other key. A client
		 * process would not have both keys, this is only for demonstration
		 * purposes.
		 */
		System.out.println("Begin Read RSA Keys.");
		FileInputStream is_private = new FileInputStream(privateKeyfile);
		FileInputStream is_public = new FileInputStream(publicKeyfile);
		RSAPrivateKey privateKey = rsa.readPrivateKey(is_private);
		RSAPublicKey publicKey = rsa.readPublicKey(is_public);
		is_public.close();
		is_private.close();
		System.out.println("End Read RSA Keys.");

		/**
		 * Use public key to encrypt a file stream directly to another file
		 * stream.
		 */
		System.out.println("Begin Encrypt Data.");
		FileOutputStream outstream = new FileOutputStream(TESTDATA_ENC_FILE);
		FileInputStream instream = new FileInputStream(TESTDATA_FILE);
		rsa.encode(instream, outstream, publicKey);
		instream.close();
		outstream.close();
		System.out.println("End Encrypt Data.");

		/**
		 * Now decrypt the encrypted file using the private key.
		 */
		System.out.println("Begin Decrypt Data.");
		outstream = new FileOutputStream(TESTDATA_DEC_FILE);
		instream = new FileInputStream(TESTDATA_ENC_FILE);
		rsa.decode(instream, outstream, privateKey);
		instream.close();
		outstream.close();
		System.out.println("End Decrypt Data.");

		/**
		 * Compare the original and decrypted files.
		 */
		String shaOriginal = DigestSHA.sha256(new FileInputStream(TESTDATA_FILE));
		String shaDecripted = DigestSHA.sha256(new FileInputStream(TESTDATA_DEC_FILE));
		if (Compare.safeEquals(shaOriginal.getBytes("UTF-8"), shaDecripted.getBytes("UTF-8")))
		{
			System.out.println("Encrypted and decrypted files are the same.");
		}
		else
		{
			System.out.println("Encrypted and decrypted files are NOT the same.");
		}
		System.out.println("End Example_010.");
	}
}
