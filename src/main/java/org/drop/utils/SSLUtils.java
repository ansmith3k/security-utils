package org.drop.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

// TODO: Auto-generated Javadoc
/**
 * The Class SSLUtils.
 */
public class SSLUtils {

	/**
	 * Gets the key store.
	 *
	 * @param sslConfig the ssl config
	 * @return the key store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getKeyStore(SSLConfig sslConfig) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		return getKeyStore(sslConfig.getKeyStoreFile(), sslConfig.getKeyStorePassword(), sslConfig.getKeyStoreType());
	}
	
	/**
	 * Gets the key store.
	 *
	 * @param keyStore the key store
	 * @param storePass the store pass
	 * @param storeType the store type
	 * @return the key store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getKeyStore(String keyStore, String storePass, String storeType) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		return getKeystore(new File(keyStore), storePass, storeType);
	}
	
	/**
	 * Gets the keystore.
	 *
	 * @param keyStoreFile the key store file
	 * @param keyStorePasswd the key store passwd
	 * @param keyStoreType the key store type
	 * @return the keystore
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws KeyStoreException the key store exception
	 */
	public static KeyStore getKeystore(File keyStoreFile, String keyStorePasswd, String keyStoreType) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		if(keyStoreFile == null) {
			throw new IllegalArgumentException("Invalid keystore. Keystore is null.");
		}
		if(!keyStoreFile.exists()) {
			throw new IllegalArgumentException("Invalid keystore. Keystore does not exist. " + keyStoreFile.getPath());
		}
		
		KeyStore keystore = null;
		try(FileInputStream inStream = new FileInputStream(keyStoreFile)){
			keystore = KeyStore.getInstance(keyStoreType);
			if(keyStorePasswd != null) {
				keystore.load(inStream, keyStorePasswd.toCharArray());
			}else {
				keystore.load(inStream, null);
			}
		}
		return keystore;
	}
	
	
	/**
	 * Gets the trust store.
	 *
	 * @param sslConfig the ssl config
	 * @return the trust store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getTrustStore(SSLConfig sslConfig) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		return getTrustStore(sslConfig.getTrustStoreFile(), sslConfig.getTrustStorePassword(), sslConfig.getTrustStoreType());
	}
	
	/**
	 * Gets the trust store.
	 *
	 * @param trustStore the trust store
	 * @param storePass the store pass
	 * @param storeType the store type
	 * @return the trust store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getTrustStore(String trustStore, String storePass, String storeType) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		return getKeystore(new File(trustStore), storePass, storeType);
	}
	
	/**
	 * Gets the empty key store.
	 *
	 * @param sslConfig the ssl config
	 * @return the empty key store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static KeyStore getEmptyKeyStore(SSLConfig sslConfig) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		return getEmptyKeyStore(sslConfig.getKeyStorePassword(), sslConfig.getKeyStoreType());
	}
	
	/**
	 * Gets the empty key store.
	 *
	 * @param keyStorePassword the key store password
	 * @param keyStoreType the key store type
	 * @return the empty key store
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws KeyStoreException the key store exception
	 */
	public static KeyStore getEmptyKeyStore(String keyStorePassword, String keyStoreType) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		if(keyStorePassword == null) {
			keyStorePassword = "";
		}
		KeyStore store = KeyStore.getInstance(keyStoreType);
		store.load(null, keyStorePassword.toCharArray());
		return store;
	}

	
	/**
	 * Gets the SSL trust bypass context.
	 *
	 * @param sslConfig the ssl config
	 * @return the SSL trust bypass context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static SSLContext getSSLTrustBypassContext(SSLConfig sslConfig) throws KeyManagementException, NoSuchAlgorithmException {
		return getSSLContext(null, getTrustManagerBypass(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	/**
	 * Gets the SSL trust bypass context.
	 *
	 * @param defaultSSLProtocol the default SSL protocol
	 * @param sRand the s rand
	 * @return the SSL trust bypass context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static SSLContext getSSLTrustBypassContext(String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException {
		return getSSLContext(null, getTrustManagerBypass(), defaultSSLProtocol, sRand);
	}
	
	/**
	 * Gets the SSL trust context.
	 *
	 * @param trustStore the trust store
	 * @param sslConfig the ssl config
	 * @return the SSL trust context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws KeyStoreException the key store exception
	 */
	public static SSLContext getSSLTrustContext(KeyStore trustStore, SSLConfig sslConfig) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		return getSSLTrustContext(trustStore, sslConfig.getTrustManagerAlgorithm(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	/**
	 * Gets the SSL trust context.
	 *
	 * @param trustStore the trust store
	 * @param trustManagerAlgorithm the trust manager algorithm
	 * @param defaultSSLProtocol the default SSL protocol
	 * @param sRand the s rand
	 * @return the SSL trust context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws KeyStoreException the key store exception
	 */
	public static SSLContext getSSLTrustContext(KeyStore trustStore, String trustManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		TrustManager[] trustManagers = getTrustManagers(trustStore, trustManagerAlgorithm);
		return getSSLContext(null, trustManagers, defaultSSLProtocol, sRand);
	}
	
	/**
	 * Gets the SSL context with trust bypass.
	 *
	 * @param keyStore the key store
	 * @param sslConfig the ssl config
	 * @return the SSL context with trust bypass
	 * @throws KeyManagementException the key management exception
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws KeyStoreException the key store exception
	 */
	public static SSLContext getSSLContextWithTrustBypass(KeyStore keyStore, SSLConfig sslConfig) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		return getSSLContextWithTrustBypass(keyStore, sslConfig.getKeyStorePassword(), sslConfig.getKeyManagerAlgorithm(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	/**
	 * Gets the SSL context with trust bypass.
	 *
	 * @param keyStore the key store
	 * @param keyStorePass the key store pass
	 * @param keyManagerAlgorithm the key manager algorithm
	 * @param defaultSSLProtocol the default SSL protocol
	 * @param sRand the s rand
	 * @return the SSL context with trust bypass
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 * @throws KeyStoreException the key store exception
	 */
	public static SSLContext getSSLContextWithTrustBypass(KeyStore keyStore, String keyStorePass, String keyManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		KeyManager[] keyManagers = getKeyManagers(keyStore, keyStorePass, keyManagerAlgorithm);
		return getSSLContext(keyManagers, getTrustManagerBypass(), defaultSSLProtocol, sRand);
	}
	
	/**
	 * Gets the SSL context.
	 *
	 * @param sslConfig the ssl config
	 * @return the SSL context
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws KeyManagementException the key management exception
	 * @throws CertificateException the certificate exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static SSLContext getSSLContext(SSLConfig sslConfig) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException, IOException {
		KeyManager[] keyManagers = null;
		if(sslConfig.hasKeyStore()) {
			keyManagers = getKeyManagers(SSLUtils.getKeyStore(sslConfig), sslConfig.getKeyStorePassword(), sslConfig.getKeyManagerAlgorithm());	
		}
		TrustManager[] trustManagers = null;
		if(!sslConfig.isTrustAllCerts()) {
			trustManagers = getTrustManagerBypass();
		}else {
			trustManagers = getTrustManagers(SSLUtils.getTrustStore(sslConfig), sslConfig.getTrustManagerAlgorithm());
		}
		return getSSLContext(keyManagers, trustManagers, sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	/**
	 * Gets the SSL context.
	 *
	 * @param keyStore the key store
	 * @param keyStorePass the key store pass
	 * @param keyManagerAlgorithm the key manager algorithm
	 * @param trustStore the trust store
	 * @param trustManagerAlgorithm the trust manager algorithm
	 * @param defaultSSLProtocol the default SSL protocol
	 * @param sRand the s rand
	 * @return the SSL context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws KeyStoreException the key store exception
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 */
	public static SSLContext getSSLContext(KeyStore keyStore, String keyStorePass, String keyManagerAlgorithm, KeyStore trustStore, String trustManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
		KeyManager[] keyManagers = getKeyManagers(keyStore, keyStorePass, keyManagerAlgorithm);
		TrustManager[] trustManagers = getTrustManagers(trustStore, trustManagerAlgorithm);
		return getSSLContext(keyManagers, trustManagers, defaultSSLProtocol, sRand);
	}
	
	/**
	 * Gets the SSL context.
	 *
	 * @param keyManagers the key managers
	 * @param trustManagers the trust managers
	 * @param defaultSSLProtocol the default SSL protocol
	 * @param sRand the s rand
	 * @return the SSL context
	 * @throws KeyManagementException the key management exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static SSLContext getSSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException {
		SecureRandom sRandom = sRand == null ? new SecureRandom() : sRand;
		SSLContext sslContext = SSLContext.getInstance(defaultSSLProtocol);
		sslContext.init(keyManagers, trustManagers, sRandom);
		return sslContext;
	}
	
	/**
	 * Gets the key managers.
	 *
	 * @param keyStore the key store
	 * @param storePass the store pass
	 * @param keyManagerAlgorithm the key manager algorithm
	 * @return the key managers
	 * @throws UnrecoverableKeyException the unrecoverable key exception
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static KeyManager[] getKeyManagers(KeyStore keyStore, String storePass, String keyManagerAlgorithm) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		String algorithm = keyManagerAlgorithm == null ? KeyManagerFactory.getDefaultAlgorithm() : keyManagerAlgorithm;
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
		keyManagerFactory.init(keyStore, storePass.toCharArray());
		return keyManagerFactory.getKeyManagers();
	}
	
	/**
	 * Gets the trust managers.
	 *
	 * @param trustStore the trust store
	 * @param trustManagerAlgorithm the trust manager algorithm
	 * @return the trust managers
	 * @throws KeyStoreException the key store exception
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 */
	public static TrustManager[] getTrustManagers(KeyStore trustStore, String trustManagerAlgorithm) throws KeyStoreException, NoSuchAlgorithmException {
		String algorithm = trustManagerAlgorithm == null ? TrustManagerFactory.getDefaultAlgorithm() : trustManagerAlgorithm;
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
		trustManagerFactory.init(trustStore);
		return trustManagerFactory.getTrustManagers();
	}
	
	
	/**
	 * Adds the asymmetric keys to key store.
	 *
	 * @param store the store
	 * @param privateKeys the private keys
	 * @throws KeyStoreException the key store exception
	 */
	public static void addAsymmetricKeysToKeyStore(KeyStore store, List<PrivateKeyInfo> privateKeys) throws KeyStoreException {
		for(PrivateKeyInfo pkInfo: privateKeys) {
			addAsymmetricKeyToKeyStore(store, pkInfo.certAlias, pkInfo.privateKey, pkInfo.privateKeyPass, pkInfo.certChain);
		}
	}
	
	/**
	 * Adds the asymmetric key to key store.
	 *
	 * @param store the store
	 * @param certAlias the cert alias
	 * @param key the key
	 * @param privateKeyPass the private key pass
	 * @param certChain the cert chain
	 * @throws KeyStoreException the key store exception
	 */
	public static void addAsymmetricKeyToKeyStore(KeyStore store, String certAlias, PrivateKey key, String privateKeyPass, X509Certificate[] certChain) throws KeyStoreException {
		if(privateKeyPass == null) {
			privateKeyPass = "";
		}
		store.setKeyEntry(certAlias, key, privateKeyPass.toCharArray(), certChain);
	}
	
	/**
	 * Adds the asymmetric keys to trust store.
	 *
	 * @param store the store
	 * @param publicKeys the public keys
	 * @throws KeyStoreException the key store exception
	 */
	public static void addAsymmetricKeysToTrustStore(KeyStore store, List<PublicKeyInfo> publicKeys) throws KeyStoreException {
		for(PublicKeyInfo pkInfo: publicKeys) {
			addAsymmetricKeyToTrustStore(store, pkInfo.certAlias, pkInfo.publicKey, pkInfo.certChain);
		}
	}
	
	/**
	 * Adds the asymmetric key to trust store.
	 *
	 * @param store the store
	 * @param certAlias the cert alias
	 * @param key the key
	 * @param certChain the cert chain
	 * @throws KeyStoreException the key store exception
	 */
	public static void addAsymmetricKeyToTrustStore(KeyStore store, String certAlias, PublicKey key, X509Certificate[] certChain) throws KeyStoreException {
		store.setKeyEntry(certAlias, key.getEncoded(), certChain);
	}
	
	/**
	 * Adds the cert to key store.
	 *
	 * @param store the store
	 * @param alias the alias
	 * @param x509 the x 509
	 * @throws KeyStoreException the key store exception
	 */
	public static void addCertToKeyStore(KeyStore store, String alias, X509Certificate x509) throws KeyStoreException {
		store.setCertificateEntry(alias, x509);
	}
	
	/**
	 * Adds the symmetric key to key store.
	 *
	 * @param store the store
	 * @param alias the alias
	 * @param secretKey the secret key
	 * @param secretPass the secret pass
	 * @throws KeyStoreException the key store exception
	 */
	public static void addSymmetricKeyToKeyStore(KeyStore store, String alias, SecretKey secretKey, String secretPass) throws KeyStoreException {
		KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(secretPass.toCharArray());
		store.setEntry(alias, secret, password);
	}
	
	/**
	 * Gets the trust manager bypass.
	 *
	 * @return the trust manager bypass
	 */
	public static TrustManager[] getTrustManagerBypass() {
		X509TrustManager x509TManager = new IgnoreTrustManager();
		return new TrustManager[] { x509TManager };
	}
	
	/**
	 * Gets the SSL supported cipher suits.
	 *
	 * @return the SSL supported cipher suits
	 */
	public static String[] getSSLSupportedCipherSuits() {
		return ((SSLServerSocketFactory)SSLServerSocketFactory.getDefault()).getSupportedCipherSuites();
	}
	
	/**
	 * The Class IgnoreTrustManager.
	 */
	public static class IgnoreTrustManager implements X509TrustManager {
		
		/**
		 * Check client trusted.
		 *
		 * @param chain the chain
		 * @param authType the auth type
		 
		 */
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) {
			// accept all			
		}

		/**
		 * Check server trusted.
		 *
		 * @param chain the chain
		 * @param authType the auth type
		 
		 */
		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) {
			// accept all
		}

		/**
		 * Gets the accepted issuers.
		 *
		 * @return the accepted issuers
		 */
		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}
	
	/**
	 * The Class IgnoreHostnameVerifier.
	 */
	public static class IgnoreHostnameVerifier implements HostnameVerifier {
		
		/**
		 * Verify.
		 *
		 * @param hostname the hostname
		 * @param session the session
		 * @return true, if successful
		 */
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	}
	
	/**
	 * The Class PrivateKeyInfo.
	 */
	public static class PrivateKeyInfo {
		
		/** The cert alias. */
		private String certAlias;
		
		/** The private key. */
		private PrivateKey privateKey;
		
		/** The private key pass. */
		private String privateKeyPass;
		
		/** The cert chain. */
		private X509Certificate[] certChain;
		
		/**
		 * Instantiates a new private key info.
		 *
		 * @param certAlias the cert alias
		 * @param privateKey the private key
		 * @param privateKeyPass the private key pass
		 * @param certChain the cert chain
		 */
		public PrivateKeyInfo(String certAlias, PrivateKey privateKey, String privateKeyPass, X509Certificate[] certChain) {
			this.certAlias = certAlias;
			this.privateKey = privateKey;
			this.privateKeyPass = privateKeyPass;
			this.certChain = certChain;
		}

		/**
		 * Gets the cert alias.
		 *
		 * @return the cert alias
		 */
		public String getCertAlias() {
			return certAlias;
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
		 * Gets the private key pass.
		 *
		 * @return the private key pass
		 */
		public String getPrivateKeyPass() {
			return privateKeyPass;
		}

		/**
		 * Gets the cert chain.
		 *
		 * @return the cert chain
		 */
		public X509Certificate[] getCertChain() {
			return certChain;
		}
	}
	
	/**
	 * The Class PublicKeyInfo.
	 */
	public static class PublicKeyInfo {
		
		/** The cert alias. */
		private String certAlias;
		
		/** The public key. */
		private PublicKey publicKey;
		
		/** The cert chain. */
		private X509Certificate[] certChain;
		
		/**
		 * Instantiates a new public key info.
		 *
		 * @param certAlias the cert alias
		 * @param publicKey the public key
		 * @param certChain the cert chain
		 */
		public PublicKeyInfo(String certAlias, PublicKey publicKey, X509Certificate[] certChain) {
			this.certAlias = certAlias;
			this.publicKey = publicKey;
			this.certChain = certChain;
		}

		/**
		 * Gets the cert alias.
		 *
		 * @return the cert alias
		 */
		public String getCertAlias() {
			return certAlias;
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
		 * Gets the cert chain.
		 *
		 * @return the cert chain
		 */
		public X509Certificate[] getCertChain() {
			return certChain;
		}
	}

}
