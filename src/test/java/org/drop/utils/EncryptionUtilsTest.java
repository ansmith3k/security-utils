package org.drop.utils;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EncryptionUtilsTest {
	
	@DisplayName("Testing Generation Secure Random Password")
	@Test
    public void EncryptionUtils_GenerateRandomPasswordUpper()
    {
		List<char[]> charSets = new ArrayList<>();
		charSets.add(EncryptionUtils.UPPER_CASE_APHABET);
		String password = EncryptionUtils.generateRandomPassword(new SecureRandom(), 25, charSets);
		log.info("UpperCase Password: " + password);
        assertTrue( !password.isEmpty() && password.length() == 25);
    }
	
	@DisplayName("Testing Generation Secure Random Password")
	@Test
    public void EncryptionUtils_GenerateRandomPasswordLower()
    {
		List<char[]> charSets = new ArrayList<>();
		charSets.add(EncryptionUtils.LOWER_CASE_APHABET);
		String password = EncryptionUtils.generateRandomPassword(new SecureRandom(), 25, charSets);
		log.info("LowerCase Password: " + password);
        assertTrue( !password.isEmpty() && password.length() == 25);
    }
	
	@DisplayName("Testing Generation Secure Random Password")
	@Test
    public void EncryptionUtils_GenerateRandomPasswordNumeric()
    {
		List<char[]> charSets = new ArrayList<>();
		charSets.add(EncryptionUtils.NUMERIC);
		String password = EncryptionUtils.generateRandomPassword(new SecureRandom(), 25, charSets);
		log.info("Numeric Password: " + password);
        assertTrue( !password.isEmpty() && password.length() == 25);
    }
	
	@DisplayName("Testing Generation Secure Random Password")
	@Test
    public void EncryptionUtils_GenerateRandomPasswordSpecial()
    {
		List<char[]> charSets = new ArrayList<>();
		charSets.add(EncryptionUtils.SPECIAL_CHARACTERS);
		String password = EncryptionUtils.generateRandomPassword(new SecureRandom(), 25, charSets);
		log.info("Special Password: " + password);
        assertTrue( !password.isEmpty() && password.length() == 25);
    }
	
	@DisplayName("Testing Generation Secure Random Password")
	@Test
    public void EncryptionUtils_GenerateRandomPasswordCombo()
    {
		List<char[]> charSets = new ArrayList<>();
		charSets.add(EncryptionUtils.UPPER_CASE_APHABET);
		charSets.add(EncryptionUtils.LOWER_CASE_APHABET);
		charSets.add(EncryptionUtils.NUMERIC);
		charSets.add(EncryptionUtils.SPECIAL_CHARACTERS);
		String password = EncryptionUtils.generateRandomPassword(new SecureRandom(), 30, charSets);
		log.info("Combo Password: " + password);
        assertTrue( !password.isEmpty() && password.length() == 30);
    }
	
	@DisplayName("Testing Symmetric Encryptiona and Decryption")
	@Test
    public void EncryptionUtils_TestSymmetricEncryptDecrypt()
    {
		byte[] salt = EncryptionUtils.generateSalt(32);
		GCMParameterSpec gcmIV = EncryptionUtils.generateGCMParameterSpec(128);
		try {
			SecretKey key = EncryptionUtils.generateNewSymmetricKey("PBKDF2WITHHMACSHA512", "AES", "password", salt, 65535, 256);
			byte[] encryptedData = EncryptionUtils.symmetricDataEncrypt("Hello world", "AES_256/GCM/NOPADDING", key, gcmIV);
			log.info("Encrypted: " + EncryptionUtils.base64URLEncode(encryptedData));
			byte[] decryptedData = EncryptionUtils.symmetricDataDecrypt(encryptedData, "AES_256/GCM/NOPADDING", key, gcmIV);
			log.info("Decrypted: " + new String(decryptedData, "UTF-8"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	
	@DisplayName("Testing Symmetric Rebuild to Decrypt")
	@Test
    public void EncryptionUtils_RebuildSymmetricEncryptDecrypt()
    {
		byte[] encryptedData = EncryptionUtils.base64URLDecode("LAANWri9jR7VJcur--StX2Nn9tca1lkCZmm1");
		byte[] salt = EncryptionUtils.base64URLDecode("lvgCMSrIWE0M9pzOfLFpKXIauVVzIZIvBE0joB12TFI=");
		GCMParameterSpec gcmIV = EncryptionUtils.base64URLToGCMSpec(128, "1SyejkhzUXzuKPWNrCCZsw==");
		System.out.println("len: " + gcmIV.getTLen() + " IV: " + EncryptionUtils.base64URLEncode(gcmIV.getIV()));
		try {
			SecretKey key = EncryptionUtils.generateNewSymmetricKey("PBKDF2WITHHMACSHA512", "AES", "password", salt, 65535, 256);
			byte[] decryptedData = EncryptionUtils.symmetricDataDecrypt(encryptedData, "AES_256/GCM/NOPADDING", key, gcmIV);
			String decrypted = new String(decryptedData, "UTF-8");
			log.info("Decrypted: " + decrypted);
			assertTrue("Hello world".equals(decrypted));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
	
	
	@DisplayName("Testing Signatures")
	@Test
    public void EncryptionUtils_TestSigningData()
    {
		try {
			KeyPairGenerator keypairGen = EncryptionUtils.getAsymmetricKeyPairGenerator("EC", 256, new SecureRandom());
			KeyPair keypair = keypairGen.generateKeyPair();
			PrivateKey privateKey = keypair.getPrivate();
			PublicKey publicKey = keypair.getPublic();
			String message = "Hello World";
			byte[] messageSignature = EncryptionUtils.signData(message, "SHA256withECDSA", privateKey);
			log.info("message signature: " + EncryptionUtils.base64URLEncode(messageSignature));
			assertTrue(EncryptionUtils.verifySignedData(message, messageSignature, "SHA256withECDSA", publicKey));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
