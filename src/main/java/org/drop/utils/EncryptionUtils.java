package org.drop.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

// TODO: Auto-generated Javadoc
/**
 * The Class EncryptionUtils.
 */
public class EncryptionUtils {
	
	/** The Constant DEFAULT_CHARSET. */
	public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
	
	/** The Constant SPECIAL_CHARACTERS. */
	public static final char[] SPECIAL_CHARACTERS = {'@', '%', '!', '#', '$', '\'', '+', ',', '/', ':', '<', '=', '>', '?', '^', '`', '~', '-', '_', '.', '\\', '[', ']', '{', '}', '(', ')'};
	
	/** The Constant NUMERIC. */
	public static final char[] NUMERIC = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
	
	/** The Constant LOWER_CASE_APHABET. */
	public static final char[] LOWER_CASE_APHABET = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
	
	/** The Constant UPPER_CASE_APHABET. */
	public static final char[] UPPER_CASE_APHABET = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
	
	
	//keyPairAlg comes from getSupportedAlgorithms("KeyPairGenerator")
	/**
	 * Gets the asymmetric key pair generator.
	 *
	 * @param keyPairAlg the key pair alg
	 * @param keySize the key size
	 * @param sRand the s rand
	 * @return the asymmetric key pair generator
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	//used to generate private/public key pair
	public static KeyPairGenerator getAsymmetricKeyPairGenerator(String keyPairAlg, int keySize, SecureRandom sRand) throws NoSuchAlgorithmException {
		SecureRandom sRandom = sRand == null ? new SecureRandom() : sRand;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairAlg);
		keyPairGenerator.initialize(keySize, sRandom);
		return keyPairGenerator;
	}
	
	/**
	 * Gets the asymmetric key pair from key store.
	 *
	 * @param keyStore the key store
	 * @param keyAlias the key alias
	 * @param keyPassword the key password
	 * @return the asymmetric key pair from key store
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static KeyPair getAsymmetricKeyPairFromKeyStore(KeyStore keyStore, String keyAlias, String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException{
		if(keyStore == null) {
			throw new IllegalArgumentException("Invalid keystore. Keystore is null.");
		}
		if(keyAlias == null) {
			throw new IllegalArgumentException("Invalid key alias. KeyAlias is null.");
		}
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
		if(privateKey == null) {
			throw new IllegalArgumentException("Invalid key alias. KeyAlias was not found in keystore.");
		}
		Certificate cert = keyStore.getCertificate(keyAlias);
		PublicKey publicKey = cert.getPublicKey();
		return new KeyPair(publicKey, privateKey);
	}
	
	/**
	 * Gets the keystore.
	 *
	 * @param keyStoreFile the key store file
	 * @param keyStorePasswd the key store passwd
	 * @param keyStoreType the key store type
	 * @return the keystore
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getKeystore(String keyStoreFile, String keyStorePasswd, String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		if(keyStoreFile == null) {
			throw new IllegalArgumentException("Invalid keystore. Keystore is null.");
		}
		return getKeystore(new File(keyStoreFile), keyStorePasswd, keyStoreType);
	}
	
	/**
	 * Gets the keystore.
	 *
	 * @param keyStoreFile the key store file
	 * @param keyStorePasswd the key store passwd
	 * @param keyStoreType the key store type
	 * @return the keystore
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getKeystore(File keyStoreFile, String keyStorePasswd, String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		if(keyStoreFile == null) {
			throw new IllegalArgumentException("Invalid keystore. Keystore is null.");
		}
		if(!keyStoreFile.exists()) {
			throw new IllegalArgumentException("Invalid keystore. Keystore does not exist. " + keyStoreFile.getPath());
		}
		KeyStore keystore = KeyStore.getInstance(keyStoreType);
		keystore.load(new FileInputStream(keyStoreFile), keyStorePasswd.toCharArray());
		return keystore;
	}
	
	/**
	 * Gets the private key from bytes.
	 *
	 * @param base64URLdata the base 64 UR ldata
	 * @param algorithm the algorithm
	 * @return the private key from bytes
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("KeyFactory")
	public static PrivateKey getPrivateKeyFromBytes(String base64URLdata, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return getPrivateKeyFromBytes(base64URLDecode(base64URLdata), algorithm);
	}
	
	/**
	 * Gets the private key from bytes.
	 *
	 * @param data the data
	 * @param algorithm the algorithm
	 * @return the private key from bytes
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("KeyFactory")
	public static PrivateKey getPrivateKeyFromBytes(byte[] data, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(spec);
	}
	
	/**
	 * Gets the public key from base 64 URL.
	 *
	 * @param base64URLdata the base 64 UR ldata
	 * @param algorithm the algorithm
	 * @return the public key from base 64 URL
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("KeyFactory")
	public static PublicKey getPublicKeyFromBase64URL(String base64URLdata, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return getPublicKeyFromBytes(base64URLDecode(base64URLdata), algorithm);
	}
	
	/**
	 * Gets the public key from bytes.
	 *
	 * @param data the data
	 * @param algorithm the algorithm
	 * @return the public key from bytes
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("KeyFactory")
	public static PublicKey getPublicKeyFromBytes(byte[] data, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePublic(spec);
	}
	
	/**
	 * Asymmetric data encrypt.
	 *
	 * @param data the data
	 * @param key the key
	 * @param cipherAlg the cipher alg
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlg comes from getSupportedAlgorithms("Cipher")
	public static byte[] asymmetricDataEncrypt(String data, Key key, String cipherAlg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		return asymmetricDataEncrypt(data.getBytes(DEFAULT_CHARSET), key, cipherAlg);
	}
	
	/**
	 * Asymmetric data encrypt.
	 *
	 * @param data the data
	 * @param charSet the char set
	 * @param key the key
	 * @param cipherAlg the cipher alg
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlg comes from getSupportedAlgorithms("Cipher")
	public static byte[] asymmetricDataEncrypt(String data, Charset charSet, Key key, String cipherAlg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		return asymmetricDataEncrypt(data.getBytes(charSet), key, cipherAlg);
	}
	
	/**
	 * Asymmetric data encrypt.
	 *
	 * @param data the data
	 * @param key the key
	 * @param cipherAlg the cipher alg
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlg comes from getSupportedAlgorithms("Cipher")
	public static byte[] asymmetricDataEncrypt(byte[] data, Key key, String cipherAlg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher encrypt = Cipher.getInstance(cipherAlg);
		encrypt.init(Cipher.ENCRYPT_MODE, key);
		return encrypt.doFinal(data);
	}
	
	/**
	 * Asymmetric data decrypt.
	 *
	 * @param data the data
	 * @param key the key
	 * @param cipherAlg the cipher alg
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlg comes from getSupportedAlgorithms("Cipher")
	public static byte[] asymmetricDataDecrypt(byte[] data, Key key, String cipherAlg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher decrypt = Cipher.getInstance(cipherAlg);
		decrypt.init(Cipher.DECRYPT_MODE, key);
		return decrypt.doFinal(data);
	}

	
	/**
	 * Sign data.
	 *
	 * @param data the data
	 * @param signatureAlg the signature alg
	 * @param privateKey the private key
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static byte[] signData(String data, String signatureAlg, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		return signData(data.getBytes(DEFAULT_CHARSET), signatureAlg, privateKey);
	}
		
	/**
	 * Sign data.
	 *
	 * @param data the data
	 * @param charSet the char set
	 * @param signatureAlg the signature alg
	 * @param privateKey the private key
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static byte[] signData(String data, Charset charSet, String signatureAlg, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		return signData(data.getBytes(charSet), signatureAlg, privateKey);
	}
	
	/**
	 * Sign data.
	 *
	 * @param data the data
	 * @param signatureAlg the signature alg
	 * @param privateKey the private key
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static byte[] signData(byte[] data, String signatureAlg, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature privateSignature = Signature.getInstance(signatureAlg);
		privateSignature.initSign(privateKey);
		privateSignature.update(data);
		byte[] signature = privateSignature.sign();
		return signature;
	}
	
	/**
	 * Verify signed data.
	 *
	 * @param data the data
	 * @param signature the signature
	 * @param signatureAlg the signature alg
	 * @param publicKey the public key
	 * @return true, if successful
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static boolean verifySignedData(String data, byte[] signature, String signatureAlg, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		return verifySignedData(data.getBytes(DEFAULT_CHARSET), signature, signatureAlg, publicKey);
	}
	
	/**
	 * Verify signed data.
	 *
	 * @param data the data
	 * @param charSet the char set
	 * @param signature the signature
	 * @param signatureAlg the signature alg
	 * @param publicKey the public key
	 * @return true, if successful
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static boolean verifySignedData(String data, Charset charSet, byte[] signature, String signatureAlg, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		return verifySignedData(data.getBytes(charSet), signature, signatureAlg, publicKey);
	}
	
	/**
	 * Verify signed data.
	 *
	 * @param data the data
	 * @param signature the signature
	 * @param signatureAlg the signature alg
	 * @param publicKey the public key
	 * @return true, if successful
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws SignatureException the signature exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	//signatureAlg comes from getSupportedAlgorithms("Signature")
	public static boolean verifySignedData(byte[] data, byte[] signature, String signatureAlg, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature privateSignature = Signature.getInstance(signatureAlg);
		privateSignature.initVerify(publicKey);
		privateSignature.update(data);
		return privateSignature.verify(signature);
	}
	
	/**
	 * Gets the random symmetric key.
	 *
	 * @param keySize the key size
	 * @param keyGenAlg the key gen alg
	 * @return the random symmetric key
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	//keyGenAlg comes from getSupportedAlgorithms("AlgorithmParameters")
	public static SecretKey getRandomSymmetricKey(int keySize, String keyGenAlg) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(keyGenAlg);
		keyGenerator.init(keySize);
		return new SecretKeySpec(keyGenerator.generateKey().getEncoded(), keyGenAlg);
	}
	
	//factoryAlogrithm comes from getSupportedAlgorithms("SecretKeyFactory")
	/**
	 * Generate new symmetric key.
	 *
	 * @param factoryAlogrithm the factory alogrithm
	 * @param keyGenAlg the key gen alg
	 * @param password the password
	 * @param salt the salt
	 * @param iterations the iterations
	 * @param keyLength the key length
	 * @return the secret key
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 */
	//keyGenAlg comes from getSupportedAlgorithms("AlgorithmParameters")
	public static SecretKey generateNewSymmetricKey(String factoryAlogrithm, String keyGenAlg, String password, byte[] salt, int iterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
	    SecretKeyFactory factory = SecretKeyFactory.getInstance(factoryAlogrithm);
	    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
	    return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), keyGenAlg);
	}
	
	/**
	 * Gets the symmetric key from bytes.
	 *
	 * @param key the key
	 * @param keyGenAlg the key gen alg
	 * @return the symmetric key from bytes
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 */
	//keyGenAlg comes from getSupportedAlgorithms("AlgorithmParameters")
	public static SecretKey getSymmetricKeyFromBytes(byte[] key, String keyGenAlg) throws NoSuchAlgorithmException, InvalidKeySpecException {
	    return new SecretKeySpec(key, keyGenAlg);
	}
	
	/**
	 * Symmetric data encrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricDataEncrypt(String data, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return symmetricDataEncrypt(data.getBytes(DEFAULT_CHARSET), cipherAlgorithm, key, iv, null);
	}
	
	/**
	 * Symmetric data encrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm; getSupportedAlgorithms("Cipher")
	 * @param key the key
	 * @param charSet the char set
	 * @param iv the iv
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	public static byte[] symmetricDataEncrypt(String data, String cipherAlgorithm, Key key, Charset charSet, AlgorithmParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return symmetricDataEncrypt(data.getBytes(charSet), cipherAlgorithm, key, iv, null);
	}
	
	/**
	 * Symmetric data encrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricDataEncrypt(String data, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return symmetricDataEncrypt(data.getBytes(DEFAULT_CHARSET), cipherAlgorithm, key, iv, addData);
	}
	
	/**
	 * Symmetric data encrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param charSet the char set
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricDataEncrypt(String data, String cipherAlgorithm, Key key, Charset charSet, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return symmetricDataEncrypt(data.getBytes(charSet), cipherAlgorithm, key, iv, addData);
	}
	
	/**
	 * Symmetric data encrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricDataEncrypt(byte[] data, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher encrypt = Cipher.getInstance(cipherAlgorithm);
		encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
		if(addData != null) {
			encrypt.update(addData);
		}
		return encrypt.doFinal(data);
	}
	
	/**
	 * Symmetric file encrypt.
	 *
	 * @param file the file
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricFileEncrypt(File file, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		Cipher encrypt = Cipher.getInstance(cipherAlgorithm);
		encrypt.init(Cipher.ENCRYPT_MODE, key, iv);
		if(addData != null) {
			encrypt.update(addData);
		}
		byte[] buffer = new byte[8192];
		try(BufferedInputStream bufInStream = new BufferedInputStream(new FileInputStream(file))) {
			int cnt = 0;
			while((cnt = bufInStream.read(buffer)) > 0) {
				encrypt.update(buffer, 0, cnt);
			}
		}
		return encrypt.doFinal();
	}
	
	/**
	 * Symmetric data decrypt.
	 *
	 * @param data the data
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricDataDecrypt(byte[] data, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher decrypt = Cipher.getInstance(cipherAlgorithm);
		decrypt.init(Cipher.DECRYPT_MODE, key, iv);
		if(addData != null) {
			decrypt.update(addData);
		}
		return decrypt.doFinal(data);
	}
	
	/**
	 * Symmetric file decrypt.
	 *
	 * @param file the file
	 * @param cipherAlgorithm the cipher algorithm
	 * @param key the key
	 * @param iv the iv
	 * @param addData the add data
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws InvalidAlgorithmParameterException the invalid algorithm parameter exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	//cipherAlgorithm comes from getSupportedAlgorithms("Cipher")
	public static byte[] symmetricFileDecrypt(File file, String cipherAlgorithm, Key key, AlgorithmParameterSpec iv, byte[] addData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		Cipher decrypt = Cipher.getInstance(cipherAlgorithm);
		decrypt.init(Cipher.DECRYPT_MODE, key, iv);
		if(addData != null) {
			decrypt.update(addData);
		}
		byte[] buffer = new byte[8192];
		try(BufferedInputStream bufInStream = new BufferedInputStream(new FileInputStream(file))) {
			int cnt = 0;
			while((cnt = bufInStream.read(buffer)) > 0) {
				decrypt.update(buffer, 0, cnt);
			}
		}
		return decrypt.doFinal();
	}
	
	/**
	 * Generate hash.
	 *
	 * @param file the file
	 * @param algorithm the algorithm
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	//algorithm comes from getSupportedAlgorithms("MessageDigest")
	public static byte[] generateHash(File file, String algorithm) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		MessageDigest digest = MessageDigest.getInstance(algorithm);
		byte[] buffer = new byte[8192];
		try(BufferedInputStream bufInStream = new BufferedInputStream(new FileInputStream(file))) {
			int cnt = 0;
			while((cnt = bufInStream.read(buffer)) > 0) {
				digest.update(buffer, 0, cnt);
			}
		}
		return digest.digest();
	}
	
	/**
	 * Generate hash.
	 *
	 * @param data the data
	 * @param algorithm the algorithm
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	//algorithm comes from getSupportedAlgorithms("MessageDigest")
	public static byte[] generateHash(String data, String algorithm) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		return generateHash(data.getBytes(), algorithm);
	}
	
	/**
	 * Generate hash.
	 *
	 * @param data the data
	 * @param algorithm the algorithm
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	//algorithm comes from getSupportedAlgorithms("MessageDigest")
	public static byte[] generateHash(byte[] data, String algorithm) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		MessageDigest digest = MessageDigest.getInstance(algorithm);
		return digest.digest(data);
	}
	
	/**
	 * Adds the security provider.
	 *
	 * @param provider the provider
	 */
	//EX: addSecurityProvider(new BouncyCastlProvider());
	public static void addSecurityProvider(Provider provider) {
		Security.addProvider(provider);
	}
	
	/**
	 * Gets the supported algorithms.
	 *
	 * @param serviceName the service name
	 * @return the supported algorithms
	 */
	//ServiceName EX: MessageDigest, Signature, Cipher, KeyGenerator, SecretKeyFactory, KeyStore, SSLContext, ... For a full list call getJavaProviders(); 
	public static Set<String> getSupportedAlgorithms(String serviceName){
		return Security.getAlgorithms(serviceName);
	}
	
	/**
	 * Gets the java providers.
	 *
	 * @return the java providers
	 */
	public static HashMap<String, Set<String>> getJavaProviders(){
		HashMap<String, Set<String>> providersMap = new HashMap<>();
		for(Provider provider: Security.getProviders()) {
			Set<String> providers = new TreeSet<>();
			providersMap.put(provider.getName(), providers);
			for(String key: provider.stringPropertyNames()) {
				providers.add(key + ":" + provider.getProperty(key));
			}
		}
		return providersMap;
	}
	
	/**
	 * Key to base 64 url.
	 *
	 * @param key the key
	 * @return the string
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static String base64URLEncode(Key key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		return base64URLEncode(key.getEncoded());
	}
	
	/**
	 * Bytes to base 64 URL.
	 *
	 * @param data the data
	 * @return the string
	 */
	public static String base64URLEncode(byte[] data) {
		return Base64.getUrlEncoder().encodeToString(data);
	}
	
	/**
	 * Base 64 URL to bytes.
	 *
	 * @param data the data
	 * @return the byte[]
	 */
	public static byte[] base64URLDecode(String data) {
		return Base64.getUrlDecoder().decode(data);
	}
	
	/**
	 * Generate salt.
	 *
	 * @param size the size
	 * @return the byte[]
	 */
	public static byte[] generateSalt(int size) {
		byte[] salt = new byte[size];
		new SecureRandom().nextBytes(salt);
		return salt;
	}
	
	/**
	 * Generate iv parameter spec.
	 *
	 * @return the iv parameter spec
	 */
	public static IvParameterSpec generateIvParameterSpec() {
		return new IvParameterSpec(generateSalt(16));
	}
	
	/**
	 * Generate iv parameter spec. common: 8, 16, 24, 32
	 *
	 * @return the iv parameter spec
	 */
	public static IvParameterSpec generateIvParameterSpec(int size) {
		return new IvParameterSpec(generateSalt(16));
	}
	
	/**
	 * Iv spec to base 64 URL.
	 *
	 * @param ivSpec the iv spec
	 * @return the string
	 */
	public static String ivSpecToBase64URL(IvParameterSpec ivSpec) {
		return base64URLEncode(ivSpec.getIV());
	}
	
	/**
	 * Base 64 URL to IV spec.
	 *
	 * @param ivSpec the iv spec
	 * @return the iv parameter spec
	 */
	public static IvParameterSpec base64URLToIVSpec(String ivSpec) {
		byte[] iv = base64URLDecode(ivSpec);
		return new IvParameterSpec(iv);
	}
		
	/**
	 * Generate GCM parameter spec.
	 *
	 * @param tagLenInBits the tag len in bits; options: 128, 120, 112, 104, or 96 only.
	 * @param iv the iv
	 * @return the GCM parameter spec
	 */
	public static GCMParameterSpec generateGCMParameterSpec(int tagLenInBits, byte[] iv) {
		return new GCMParameterSpec(tagLenInBits, iv);
	}
	
	/**
	 * Generate GCM parameter spec.
	 *
	 * @param tagLenInBits the tag len in bits; options: 128, 120, 112, 104, or 96 only. 
	 * @return the GCM parameter spec
	 */
	public static GCMParameterSpec generateGCMParameterSpec(int tagLenInBits) {
		return generateGCMParameterSpec(tagLenInBits, generateSalt(16));
	}
	
	/**
	 * Generate random password.
	 *
	 * @param sRandom the s random
	 * @param length the length
	 * @param charSets the char sets
	 * @return the string
	 */
	public static String generateRandomPassword(SecureRandom sRandom, int length, List<char[]> charSets) {
		if(charSets.isEmpty()) {
			return "";
		}
		if(sRandom == null) {
			sRandom = new SecureRandom();
		}
		final int charSetMax = charSets.size()-1;
		final int charSetMin = 0;
		int charMin = 0;
		
		int charSetIndex;
		int charMax;
		char[] data = null;
		StringBuilder pass = new StringBuilder();
		for(int i = 0; i < length; i++) {
			charSetIndex = (sRandom.nextInt(charSetMax - charSetMin + 1) + charSetMin);
			data = charSets.get(charSetIndex);
			charMax = data.length - 1;
			pass.append(data[sRandom.nextInt(charMax - charMin + 1) + charMin]);
		}
		return pass.toString();
	}
}
