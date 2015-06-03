package org.albertschmitt.cryptography.examples;


import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import static org.albertschmitt.crypto.AESService.SALT_SIZE;

public class Example_060
{

	public static void main(String[] args) throws Exception
	{
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

		if (clear_text.equals(dec_text))
		{
			System.out.println("Original and Decrypted are the same!");
		}
		else
		{
			System.out.println("Original and Decrypted are NOT the same!");
		}
	}
}
