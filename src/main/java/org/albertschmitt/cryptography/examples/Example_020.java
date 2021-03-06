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
import java.io.File;
import java.io.FileInputStream;
import org.albertschmitt.crypto.RSAService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;

/**
 * Example 020.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Check for existence of RSA Keys.</li>
 * <li>Generate RSA.</li>
 * <li>Read RSA Keys.</li>
 * <li>Encrypt and Decrypt a data file using byte arrays.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_020
{

	private static final String TESTDATA_FILE = "./Example_020.txt";
	private static final String privateKeyfile = "./Example_020_private_key.pem";
	private static final String publicKeyfile = "./Example_020_public_key.pem";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_020.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		/**
		 * Create a public / private RS key pair.
		 */
		final RSAService rsa = new RSAService();
		if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
		{
			System.out.println("Begin Create RSA Keys.");
			rsa.generateKey(privateKeyfile, publicKeyfile);
			System.out.println("End Create RSA Keys.");
		}

		/**
		 * RSA keys are asynchronous; there is a public and private key. Each
		 * key can only decrypt data encrypted with the other key. A client
		 * process would not have both keys, this is only for demonstration
		 * purposes.
		 */
		System.out.println("Begin Read RSA Keys.");
		RSAPrivateKey privateKey = rsa.readPrivateKey(privateKeyfile);
		RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
		System.out.println("End Read RSA Keys.");

		/**
		 * Read the test data into a byte array. Be sure to use UTF-8 when
		 * converting between strings and byte arrays.
		 */
		System.out.println("Begin Read Data.");
		File file = new File(TESTDATA_FILE);
		StringBuilder sb;
		try (FileInputStream instream = new FileInputStream(file))
		{
			sb = new StringBuilder();
			int ch;
			while ((ch = instream.read()) != -1)
			{
				sb.append(ch);
			}
		}
		byte[] testdata_bytes = sb.toString().getBytes("UTF-8");
		System.out.println("End Read Data.");

		/**
		 * Use public key to encrypt a byte array to another byte array.
		 */
		System.out.println("Begin Encrypt Data.");
		byte[] testdata_enc = rsa.encode(testdata_bytes, publicKey);
		System.out.println("End Encrypt Data.");

		/**
		 * Now decrypt the encrypted file using the private key.
		 */
		System.out.println("Begin Decrypt Data.");
		byte[] testdata_dec = rsa.decode(testdata_enc, privateKey);
		System.out.println("End Decrypt Data.");

		/**
		 * Compare the original and decrypted files.
		 */
		String shaOriginal = DigestSHA.sha256(testdata_bytes);
		String shaDecripted = DigestSHA.sha256(testdata_dec);
		if (Compare.safeEquals(shaOriginal.getBytes("UTF-8"), shaDecripted.getBytes("UTF-8")))
		{
			System.out.println("Encrypted and decrypted files are the same.");
		}
		else
		{
			System.out.println("Encrypted and decrypted files are NOT the same.");
		}
		System.out.println("End Example_020.");
	}
}
