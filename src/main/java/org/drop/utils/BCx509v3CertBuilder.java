package org.drop.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.BigIntegers;

/**
 * The Class BCx509v3CertBuilder.
 */
public class BCx509v3CertBuilder {

	/** The Constant DEFAULT_ENCRYPTION_TYPE. */
	public static final String DEFAULT_ENCRYPTION_TYPE = "EC";
	
	/** The Constant DEFAULT_KEY_SIZE. */
	public static final int DEFAULT_KEY_SIZE = 384;
	
	/** The Constant DEFAULT_SECURE_RANDOM_ALG. */
	public static final String DEFAULT_SECURE_RANDOM_ALG = "SHA1PRNG";
	
	/** The Constant DEFAULT_EC_SIGNING_ALG. */
	public static final String DEFAULT_EC_SIGNING_ALG = "SHA384withECDSA";
	
	/** The Constant DEFAULT_RSA_SIGNING_ALG. */
	public static final String DEFAULT_RSA_SIGNING_ALG = "SHA512withRSA";
	
	/** The Constant DEFAULT_KEYSTORE_TYPE. */
	public static final String DEFAULT_KEYSTORE_TYPE = "pkcs12";
	
	/** The Constant DEFAULT_CERT_VALID_DAYS. */
	public static final Long DEFAULT_CERT_VALID_DAYS = 90L;
	
	/** The key pair generator. */
	private KeyPairGenerator keyPairGenerator;
	
	/** The public key. */
	private PublicKey publicKey;
	
	/** The private key. */
	private PrivateKey privateKey;
	
	/** The secure random. */
	private SecureRandom secureRandom = null;
	
	/** The secure random alg. */
	private String secureRandomAlg = DEFAULT_SECURE_RANDOM_ALG;
	
	/** The key pair generator key size. */
	private int keyPairGeneratorKeySize = DEFAULT_KEY_SIZE;
	
	/** The encryption type. */
	private String encryptionType = DEFAULT_ENCRYPTION_TYPE;

	/** The cert valid num of days. */
	private Long certValidNumOfDays = DEFAULT_CERT_VALID_DAYS;
	
	/** The not before time. */
	private Time notBeforeTime;
	
	/** The not after time. */
	private Time notAfterTime;
	
	/** The issuer DN. */
	private X500Name issuerDN;
	
	/** The aliases. */
	private GeneralNames aliases;
	
	
	/**
	 * Instantiates a new b cx 509 v 3 cert builder.
	 *
	 * @param issuerDN the issuer DN
	 */
	public BCx509v3CertBuilder(X500Name issuerDN){
		if(issuerDN == null) {
			throw new IllegalArgumentException("Invalid issuerDN. issuerDN is null.");
		}
		this.issuerDN = issuerDN;
	}
	
	/**
	 * Sets the cert lenght in days.
	 *
	 * @param numOfDays the new cert lenght in days
	 */
	public void setCertLenghtInDays(Long numOfDays) {
		certValidNumOfDays = numOfDays;
	}
	
	/**
	 * Gets the cert lenght in days.
	 *
	 * @return the cert lenght in days
	 */
	public Long getCertLenghtInDays() {
		return certValidNumOfDays;
	}
	
	/**
	 * Gets the key pair generator.
	 *
	 * @return the key pair generator
	 */
	public KeyPairGenerator getKeyPairGenerator() {
		return keyPairGenerator;
	}
	
	/**
	 * Sets the key pair generator.
	 *
	 * @param keyPairGenerator the new key pair generator
	 */
	public void setKeyPairGenerator(KeyPairGenerator keyPairGenerator) {
		this.keyPairGenerator = keyPairGenerator;
	}
	
	/**
	 * Gets the public key.
	 *
	 * @return the public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * Sets the public key.
	 *
	 * @param publicKey the new public key
	 */
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	/**
	 * Gets the private key.
	 *
	 * @return the private key
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	/**
	 * Sets the private key.
	 *
	 * @param privateKey the new private key
	 */
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * Gets the secure random.
	 *
	 * @return the secure random
	 */
	public SecureRandom getSecureRandom() {
		return secureRandom;
	}
	
	/**
	 * Sets the secure random.
	 *
	 * @param secureRandom the new secure random
	 */
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}
	
	/**
	 * Gets the secure random alg.
	 *
	 * @return the secure random alg
	 */
	public String getSecureRandomAlg() {
		return secureRandomAlg;
	}
	
	/**
	 * Sets the secure random alg.
	 *
	 * @param secureRandomAlg the new secure random alg
	 */
	public void setSecureRandomAlg(String secureRandomAlg) {
		this.secureRandomAlg = secureRandomAlg;
	}
	
	/**
	 * Gets the key pair generator key size.
	 *
	 * @return the key pair generator key size
	 */
	public int getKeyPairGeneratorKeySize() {
		return keyPairGeneratorKeySize;
	}
	
	/**
	 * Sets the key pair generator key size.
	 *
	 * @param keyPairGeneratorKeySize the new key pair generator key size
	 */
	public void setKeyPairGeneratorKeySize(int keyPairGeneratorKeySize) {
		this.keyPairGeneratorKeySize = keyPairGeneratorKeySize;
	}
	
	/**
	 * Gets the encryption type.
	 *
	 * @return the encryption type
	 */
	public String getEncryptionType() {
		return encryptionType;
	}
	
	/**
	 * Sets the encryption type.
	 *
	 * @param encryptionType the new encryption type
	 */
	public void setEncryptionType(String encryptionType) {
		this.encryptionType = encryptionType;
	}
	
	
	/**
	 * Gets the not before time.
	 *
	 * @return the not before time
	 */
	public Time getNotBeforeTime() {
		return notBeforeTime;
	}
	
	/**
	 * Sets the not before time.
	 *
	 * @param notBeforeTime the new not before time
	 */
	public void setNotBeforeTime(Time notBeforeTime) {
		this.notBeforeTime = notBeforeTime;
	}
	
	/**
	 * Gets the not after time.
	 *
	 * @return the not after time
	 */
	public Time getNotAfterTime() {
		return notAfterTime;
	}
	
	/**
	 * Sets the not after time.
	 *
	 * @param notAfterTime the new not after time
	 */
	public void setNotAfterTime(Time notAfterTime) {
		this.notAfterTime = notAfterTime;
	}
	
	/**
	 * Gets the issuer DN.
	 *
	 * @return the issuer DN
	 */
	public X500Name getIssuerDN() {
		return issuerDN;
	}
	
	/**
	 * Gets the aliases.
	 *
	 * @return the aliases
	 */
	public GeneralNames getAliases() {
		return aliases;
	}
	
	/**
	 * Sets the aliases.
	 *
	 * @param aliases the new aliases
	 */
	public void setAliases(GeneralNames aliases) {
		this.aliases = aliases;
	}
	
	/**
	 * Builds the.
	 *
	 * @param subjectDN the subject DN
	 * @return the x 509 v 3 certificate builder
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws CertIOException the cert IO exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public X509v3CertificateBuilder build(X500Name subjectDN) throws NoSuchAlgorithmException, IllegalArgumentException, CertIOException, IOException {
		if(subjectDN == null) {
			throw new IllegalArgumentException("Invalid subjectDN. subjectDN is null.");
		}
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
		
		BigInteger serial = BigIntegers.createRandomBigInteger(64, secureRandom);
		
		if(notBeforeTime == null) {
			notBeforeTime = BCUtils.getTime(LocalDateTime.now(), ZoneId.systemDefault());
		}
		
		if(notAfterTime == null) {
			if(certValidNumOfDays > 0) {
				notAfterTime = BCUtils.getTime(LocalDateTime.now().plusDays(certValidNumOfDays), ZoneId.systemDefault());	
			}else {
				notAfterTime = BCUtils.getTime(LocalDateTime.now().plusDays(DEFAULT_CERT_VALID_DAYS), ZoneId.systemDefault());
			}
		}
		
		byte[] publicKeyEnc = publicKey.getEncoded();
		SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKeyEnc));
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerDN, serial, notBeforeTime, notAfterTime, subjectDN, subjectPublicKeyInfo);
		SubjectKeyIdentifier subjectKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId.getEncoded());
		if(aliases != null) {
			certBuilder.addExtension(Extension.subjectAlternativeName, false, aliases);
		}
		return certBuilder;
	}
	
}
