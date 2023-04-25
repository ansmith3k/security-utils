package org.drop.utils;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

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
}
