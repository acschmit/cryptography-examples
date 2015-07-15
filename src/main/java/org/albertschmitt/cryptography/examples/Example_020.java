/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.albertschmitt.cryptography.examples;

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
 * <li>Generate RSA Keys using filename string.</li>
 * <li>Read RSA Keys using filename string.</li>
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
		FileInputStream instream = new FileInputStream(file);
		StringBuilder sb = new StringBuilder();
		int ch;
		while ((ch = instream.read()) != -1)
		{
			sb.append(ch);
		}
		instream.close();
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
