package org.drop.utils;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class test {

	public static void main(String[] args) {

		
		byte[] salt = EncryptionUtils.generateSalt(32);
		GCMParameterSpec gcmIV = EncryptionUtils.generateGCMParameterSpec(128);
		try {
			//System.out.println(EncryptionUtils.base64URLEncode(EncryptionUtils.generateHash(salt, "sha-256")));
			System.out.println(EncryptionUtils.getSupportedAlgorithms("SecretKeyFactory"));
			System.out.println(EncryptionUtils.getSupportedAlgorithms("KeyGenerator"));
			System.out.println(EncryptionUtils.getSupportedAlgorithms("Cipher"));
			System.out.println("salt: "  + EncryptionUtils.base64URLEncode(salt));
			System.out.println("len: " + gcmIV.getTLen() + " IV: \"" + EncryptionUtils.base64URLEncode(gcmIV.getIV()) + "\"");
			
			GCMParameterSpec gcmIV2 = EncryptionUtils.base64URLToGCMSpec(gcmIV.getTLen(), EncryptionUtils.base64URLEncode(gcmIV.getIV()));
			
			System.out.println("len: " + gcmIV.getTLen() + " IV: " + EncryptionUtils.base64URLEncode(gcmIV.getIV()));
			//String factoryAlogrithm, String keyGenAlg, String password, byte[] salt, int iterations, int keyLength
			SecretKey key = EncryptionUtils.generateNewSymmetricKey("PBKDF2WITHHMACSHA512", "AES", "password", salt, 65535, 256);
			System.out.println("key: " + EncryptionUtils.base64URLEncode(key.getEncoded()));
			byte[] encryptedData = EncryptionUtils.symmetricDataEncrypt("Hello world", "AES_256/GCM/NOPADDING", key, gcmIV);
			System.out.println("Encrypted: " + EncryptionUtils.base64URLEncode(encryptedData));
			byte[] decryptedData = EncryptionUtils.symmetricDataDecrypt(encryptedData, "AES_256/GCM/NOPADDING", key, gcmIV2);
			System.out.println("Decrypted: " + new String(decryptedData, "UTF-8"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
