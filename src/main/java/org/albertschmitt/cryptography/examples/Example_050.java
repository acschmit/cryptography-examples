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
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;

/**
 * Example 050.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Create an AES Key.</li>
 * <li>Use AES Key to encrypt a string.</li>
 * <li>Get the AES Key bytes.</li>
 * <li>Use AES key to encrypt a from one file stream to another.</li>
 * <li>Create an AES Key using the key bytes from before.</li>
 * <li>Decrypt the encrypted file using the AES key.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_050
{

	private static final String TESTDATA_DEC_FILE = "./Example_050.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_050.enc.txt";
	private static final String TESTDATA_FILE = "./Example_050.txt";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_050.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		/**
		 * Create a 256-bit AES key. AES keys are synchronous. One key can both
		 * encrypt and decrypt data.
		 */
		System.out.println("Begin Create AES Key.");
		AESService aesServer = new AESService();
		aesServer.generateKey();
		System.out.println("End Create AES Key.");

		/**
		 * When generating a key without a username and salt, the server would
		 * get the AES key bytes and encrypt them using an RSA private key. The
		 * server would then send the encrypted key bytes to the client along
		 * with a message encrypted with the AES key. The client would then
		 * decrypt the AES key with its public key, use it to recreate the AES
		 * key then decrypt the message.
		 */
		byte[] aes_key = aesServer.getAesKey();

		/**
		 * Use AES key to encrypt a file stream directly to another file stream.
		 */
		System.out.println("Begin Encrypt Data.");
		try (FileOutputStream outstream = new FileOutputStream(TESTDATA_ENC_FILE);
			 FileInputStream instream = new FileInputStream(TESTDATA_FILE))
		{
			aesServer.encode(instream, outstream);
		}
		System.out.println("End Encrypt Data.");

		/**
		 * Imagine a client process has received the AES key from the server
		 * encrypted using RSA. The client decrypts the AES key bytes using its
		 * public key and uses AES key bytes to recreate the same AES key.
		 */
		AESService aesClient = new AESService();
		aesClient.setAesKey(aes_key);

		/**
		 * Now decrypt the encrypted file using the same AES key.
		 */
		System.out.println("Begin Decrypt Data.");
		try (FileOutputStream outstream = new FileOutputStream(TESTDATA_DEC_FILE);
			 FileInputStream instream = new FileInputStream(TESTDATA_ENC_FILE))
		{
			aesClient.decode(instream, outstream);
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
		System.out.println("End Example_050.");
	}
}
