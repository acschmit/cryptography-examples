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

import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.common.Compare;
import org.albertschmitt.crypto.common.HMAC;
import org.albertschmitt.crypto.common.Hex;

/**
 * Example 060.
 * <p>
 * Demonstrate the following techniques:</p>
 * <ul>
 * <li>Generate a message hash using HMAC256 and a secret key from some
 * content.</li>
 * <li>Encrypt the content and simulate sending everything to a server
 * process.</li>
 * <li>Server decrypts the encrypted content.</li>
 * <li>Server generates a message hash from decrypted content and the secret
 * key.</li>
 * <li>Server compares its message hash to the client's message hash. </li>
 * </ul>
 *
 * @author Albert Schmitt [acschmit] [at] [gmail] [dot] [com]
 */
public class Example_070
{

	private static String secret_key = "secret-shared-key";
	private static String content = "Lorem ipsum dolor sit amet, duo cu nobis epicurei hendrerit, mei agam elit an.";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_070.");

		AESService aes = new AESService();
		aes.generateKey();

		/**
		 * Simulate a client that is going to send encrypted data along with a
		 * verification hash.
		 */
		String hmacClient = HMAC.sha256(content, secret_key);
		byte[] encData = aes.encode(content);
		System.out.println("HMAC_sha256: " + hmacClient);

		/**
		 * Simulate the server that receives the encrypted data and verification
		 * hash. Assume it has the same secret key, password and salt as the
		 * client.
		 *
		 * The server would construct a new AES key using the password and salt
		 * then compare the digest hash to the one the client sent. If they
		 * match, the message hasn't been tampered with en-route.
		 */
		byte[] decData = aes.decode(encData);
		final String server_content = new String(decData, "UTF-8");
		String hmacServer = HMAC.sha256(server_content, secret_key);
		if (hmacServer.compareTo(hmacClient) == 0)
		{
			System.out.println("Encrypted data from client verifed.");
			System.out.format("Client content was: %s\n", server_content);
		}
		else
		{
			System.out.println("Encrypted data from client was tampered with en-route.");
			System.out.println("Client content should not be trusted.");
		}

		System.out.println("End Example_070.");
	}
}
