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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.RSAService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;

/**
 * Example 040.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Create a public / private RSA key pair.</li>
 * <li>Generate an AES key then RSA encrypt it and write it to a file.</li>
 * <li>Use AES key to encrypt a file stream directly to another file
 * stream.</li>
 * <li>Decrypt the encrypted file using the same AES key.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_040
{

	private static final String TESTDATA_DEC_FILE = "./Example_040.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_040.enc.txt";
	private static final String TESTDATA_FILE = "./Example_040.txt";

	private static final String publicKeyfile = "./Example_040_public_key.pem";
	private static final String keyFile = "./Example_040_keybytes.dat";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_040.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		final RSAService rsa = new RSAService();
		File f = new File(publicKeyfile);
		if (!f.exists())
		{
			/**
			 * Create a public / private RSA key pair.
			 */
			System.out.println("Begin Create RSA Keys.");

			InputStream bis_private;
			try (ByteArrayOutputStream bos_private = new ByteArrayOutputStream();
				 FileOutputStream fos_public = new FileOutputStream(publicKeyfile))
			{
				rsa.generateKey(bos_private, fos_public);
				bis_private = new ByteArrayInputStream(bos_private.toByteArray());
			}

			System.out.println("End Create RSA Keys.");

			/**
			 * Generate an AES key then RSA encrypt it and write it to a file.
			 */
			System.out.println("Begin Create AES Key.");
			final AESService aes = new AESService();
			aes.generateKey();
			final byte[] key_bytes = aes.getAesKey();
			System.out.println("End Create AES Key.");

			System.out.println("Begin Encrypt AES Key.");
			final RSAPrivateKey privateKey = rsa.readPrivateKey(bis_private);
			final byte[] data = rsa.encode(key_bytes, privateKey);
			System.out.println("End Encrypt AES Key.");

			/**
			 * Write encrypted AES key to file.
			 */
			final Path path = Paths.get(keyFile);
			Files.write(path, data, StandardOpenOption.CREATE);
		}

		final Path path = Paths.get(keyFile);
		final byte[] data = Files.readAllBytes(path);

		final RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
		final byte[] key_bytes = rsa.decode(data, publicKey);

		final AESService aes = new AESService();
		aes.setAesKey(key_bytes);

		/**
		 * Use AES key to encrypt a file stream directly to another file stream.
		 */
		System.out.println("Begin Encrypt Data.");
		FileOutputStream outstream = new FileOutputStream(TESTDATA_ENC_FILE);
		FileInputStream instream = new FileInputStream(TESTDATA_FILE);
		aes.encode(instream, outstream);
		instream.close();
		outstream.close();
		System.out.println("End Encrypt Data.");

		/**
		 * Now decrypt the encrypted file using the same AES key.
		 */
		System.out.println("Begin Decrypt Data.");
		outstream = new FileOutputStream(TESTDATA_DEC_FILE);
		instream = new FileInputStream(TESTDATA_ENC_FILE);
		aes.decode(instream, outstream);
		instream.close();
		outstream.close();
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
		System.out.println("End Example_040.");
	}
}
