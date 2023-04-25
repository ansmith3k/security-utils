package org.drop.utils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class test {

	public static void main(String[] args) {

		
		byte[] salt = EncryptionUtils.generateSalt(32);
		try {
			System.out.println(EncryptionUtils.base64URLEncode(EncryptionUtils.generateHash(salt, "sha-256")));
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
