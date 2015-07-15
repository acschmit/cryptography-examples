/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.albertschmitt.cryptography.examples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.DigestSHA;

/**
 * Example 030.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Generate AES Key.</li>
 * <li>Use AES key to encrypt a file stream directly to another file stream</li>
 * <li>Decrypt the encrypted file using the same AES key</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_030
{

	private static final String TESTDATA_DEC_FILE = "./Example_030.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_030.enc.txt";
	private static final String TESTDATA_FILE = "./Example_030.txt";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_030.");
		// Create some data to test with.
		Support.testData(TESTDATA_FILE);

		/**
		 * Create a 256-bit AES key. AES keys are synchronous. One key can both
		 * encrypt and decrypt data.
		 */
		System.out.println("Begin Create AES Key.");
		AESService aes = new AESService();
		aes.generateKey();
		System.out.println("End Create AES Key.");

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
		System.out.println("End Example_030.");
	}
}
