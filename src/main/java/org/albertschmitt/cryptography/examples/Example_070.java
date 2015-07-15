/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.albertschmitt.cryptography.examples;

import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.common.HMAC;
import org.albertschmitt.crypto.common.Hex;

/**
 *
 * @author acschmit
 */
public class Example_070
{

	public static void main(String[] args) throws Exception
	{

		System.out.println("Begin Example_070.");
		String password = "password1";
		String secret_key = "secret-shared-key";
		String content = "Lorem ipsum dolor sit amet, duo cu nobis epicurei hendrerit, mei agam elit an.";

		String hmac = HMAC.sha256(content, secret_key);
		System.out.println("HMAC_sha256: " + hmac);

		String hex_string = Hex.encode(content.getBytes("UTF-8"));
		System.out.println("Content Hex String: " + hex_string);

		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[AESService.SALT_SIZE];
		random.nextBytes(salt);

		hmac = HMAC.sha256(content, password);
		System.out.println("HMAC_sha256: " + hmac);
		System.out.println("End Example_070.");
	}
}
