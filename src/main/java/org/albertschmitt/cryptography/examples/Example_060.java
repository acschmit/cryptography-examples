package org.albertschmitt.cryptography.examples;

import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import static org.albertschmitt.crypto.AESService.SALT_SIZE;
import org.albertschmitt.crypto.common.Compare;

/**
 * Example 060.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Create an AES Key using password and salt.</li>
 * <li>Use AES Key to encrypt a string.</li>
 * <li>Decrypt the encrypted string.</li>
 * <li>Compare the decrypted file to the original.</li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_060
{

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_060.");
		// Create the AES Service
		AESService aes = new AESService();

		String password = "password";
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_SIZE];
		random.nextBytes(salt);

		// Create the AES Key using password and salt.
		aes.generateKey(password, salt);

		// Encode and Decode a string then compare to verify they are the same.
		String clear_text = "This is a test";
		byte[] enc_bytes = aes.encode(clear_text.getBytes("UTF-8"));
		byte[] dec_bytes = aes.decode(enc_bytes);
		String dec_text = new String(dec_bytes, "UTF-8");

		/**
		 * Compare the original and decrypted files.
		 */
		if (Compare.safeEquals(clear_text.getBytes("UTF-8"), dec_text.getBytes("UTF-8")))

		{
			System.out.println("Original and Decrypted are the same!");
		}
		else
		{
			System.out.println("Original and Decrypted are NOT the same!");
		}
		System.out.println("End Example_060.");
	}
}
