package org.drop.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.sql.Time;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class BCx509v3CertBuilder {

	public static final String DEFAULT_ENCRYPTION_TYPE = "EC";
	public static final int DEFAULT_KEY_SIZE = 384;
	public static final String DEFAULT_SECURE_RANDOM_ALG = "SHA1PRNG";
	public static final String DEFAULT_EC_SIGNING_ALG = "SHA384withECDSA";
	public static final String DEFAULT_RSA_SIGNING_ALG = "SHA512withRSA";
	public static final String DEFAULT_KEYSTORE_TYPE = "pkcs12";
	
	private KeyPairGenerator keyPairGenerator;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	private SecureRandom secureRandom = null;
	private String secureRandomAlg = DEFAULT_SECURE_RANDOM_ALG;
	
	private int keyPairGeneratorKeySize = DEFAULT_KEY_SIZE;
	private String encryptionType = DEFAULT_ENCRYPTION_TYPE;
	
	private BigInteger serial;
	private Time notBeforeTime;
	private Time notAfterTime;
	private X500Name subjectDN;
	private X500Name issuerDN;
	private GeneralNames aliases;
	
	public KeyPairGenerator getKeyPairGenerator() {
		return keyPairGenerator;
	}
	public void setKeyPairGenerator(KeyPairGenerator keyPairGenerator) {
		this.keyPairGenerator = keyPairGenerator;
	}
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	public SecureRandom getSecureRandom() {
		return secureRandom;
	}
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}
	public String getSecureRandomAlg() {
		return secureRandomAlg;
	}
	public void setSecureRandomAlg(String secureRandomAlg) {
		this.secureRandomAlg = secureRandomAlg;
	}
	public int getKeyPairGeneratorKeySize() {
		return keyPairGeneratorKeySize;
	}
	public void setKeyPairGeneratorKeySize(int keyPairGeneratorKeySize) {
		this.keyPairGeneratorKeySize = keyPairGeneratorKeySize;
	}
	public String getEncryptionType() {
		return encryptionType;
	}
	public void setEncryptionType(String encryptionType) {
		this.encryptionType = encryptionType;
	}
	public BigInteger getSerial() {
		return serial;
	}
	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}
	public Time getNotBeforeTime() {
		return notBeforeTime;
	}
	public void setNotBeforeTime(Time notBeforeTime) {
		this.notBeforeTime = notBeforeTime;
	}
	public Time getNotAfterTime() {
		return notAfterTime;
	}
	public void setNotAfterTime(Time notAfterTime) {
		this.notAfterTime = notAfterTime;
	}
	public X500Name getSubjectDN() {
		return subjectDN;
	}
	public void setSubjectDN(X500Name subjectDN) {
		this.subjectDN = subjectDN;
	}
	public X500Name getIssuerDN() {
		return issuerDN;
	}
	public void setIssuerDN(X500Name issuerDN) {
		this.issuerDN = issuerDN;
	}
	public GeneralNames getAliases() {
		return aliases;
	}
	public void setAliases(GeneralNames aliases) {
		this.aliases = aliases;
	}
	
	public X509v3CertificateBuilder build() throws NoSuchAlgorithmException {
		if(secureRandom == null) {
			secureRandom = SecureRandom.getInstance(secureRandomAlg);
		}
		if(privateKey == null || publicKey == null) {
			if(keyPairGenerator == null) {
				keyPairGenerator = KeyPairGenerator.getInstance(encryptionType);
			}
			keyPairGenerator.initialize(keyPairGeneratorKeySize, secureRandom);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
		}
		
		if(subjectDN == null || issuerDN == null) {
			//subjectDN = BCU
			return null;
		}
		return null;
		
	}
	
}
