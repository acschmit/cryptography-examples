/*
 * The MIT License
 *
 * Copyright 2015 acschmit.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.albertschmitt.cryptography.examples;

import org.albertschmitt.cryptography.support.Support;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;
import org.albertschmitt.cryptography.support.RSAService4K;

/**
 * Example 015.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Check for existence of RSA Keys.</li>
 * <li>Extend the RSAService class to create a class that will perform 4096-bit
 * encryption.</li>
 * <li>Generate 4096-bit RSA Keys using a password.</li>
 * <li>Read RSA Keys using a password.</li>
 * <li>Encrypt and Decrypt a data file using streams.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_015
{

	private static final String TESTDATA_DEC_FILE = "./Example_010a.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_010a.enc.txt";
	private static final String TESTDATA_FILE = "./Example_010a.txt";
	private static final String privateKeyfile = "./Example_010a_private_key.pem";
	private static final String publicKeyfile = "./Example_010a_public_key.pem";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_015.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		/**
		 * Get password input from user. Char array to prevent memory hacking.
		 */
		char[] charPassword = new char[]
		{
			'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
		};

		/**
		 * Create a public / private RSA key pair.
		 */
		final RSAService4K rsa = new RSAService4K();
		if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
		{
			rsa.generateKey(privateKeyfile, publicKeyfile, charPassword);
		}

		/**
		 * RSA keys are asynchronous; there is a public and private key. Each
		 * key can only decrypt data encrypted with the other key. A client
		 * process would not have both keys, this is only for demonstration
		 * purposes.
		 */
		System.out.println("Begin Read RSA Keys.");
		RSAPrivateKey privateKey = rsa.readPrivateKey(privateKeyfile, charPassword);
		RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
		System.out.println("End Read RSA Keys.");

		/**
		 * Erase password to prevent memory hacking.
		 */
		for (int i = 0; i < charPassword.length; i++)
		{
			charPassword[i] = ' ';
		}

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
		System.out.println("End Example_015.");
	}
}
