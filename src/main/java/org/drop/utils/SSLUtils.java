package org.drop.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
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

public class SSLUtils {

	public static KeyStore getKeyStore(SSLConfig sslConfig) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
		return getKeyStore(sslConfig.getKeyStoreFile(), sslConfig.getKeyStorePassword(), sslConfig.getKeyStoreType());
	}
	
	public static KeyStore getKeyStore(String keyStore, String storePass, String storeType) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
		KeyStore store = null;
		try(FileInputStream inStream = new FileInputStream(keyStore)){
			store = KeyStore.getInstance(storeType);
			store.load(inStream, storePass.toCharArray());
		}
		return store;
	}
	
	public static KeyStore getTrustStore(SSLConfig sslConfig) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
		return getTrustStore(sslConfig.getTrustStoreFile(), sslConfig.getTrustStorePassword(), sslConfig.getTrustStoreType());
	}
	
	public static KeyStore getTrustStore(String trustStore, String storePass, String storeType) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
		KeyStore store = null;
		try(FileInputStream inStream = new FileInputStream(trustStore)){
			store = KeyStore.getInstance(storeType);
			store.load(inStream, storePass.toCharArray());
		}
		return store;
	}
	
	public static KeyStore getEmptyKeyStore(SSLConfig sslConfig) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException  {
		return getEmptyKeyStore(sslConfig.getKeyStorePassword(), sslConfig.getKeyStoreType());
	}
	
	public static KeyStore getEmptyKeyStore(String keyStorePassword, String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException  {
		if(keyStorePassword == null) {
			keyStorePassword = "";
		}
		KeyStore store = KeyStore.getInstance(keyStoreType);
		store.load(null, keyStorePassword.toCharArray());
		return store;
	}

	public static SSLContext getSSLTrustBypassContext(SSLConfig sslConfig) throws KeyManagementException, NoSuchAlgorithmException {
		return getSSLContext(null, getTrustManagerBypass(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	public static SSLContext getSSLTrustBypassContext(String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException {
		return getSSLContext(null, getTrustManagerBypass(), defaultSSLProtocol, sRand);
	}
	
	public static SSLContext getSSLTrustContext(KeyStore trustStore, SSLConfig sslConfig) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		return getSSLTrustContext(trustStore, sslConfig.getTrustManagerAlgorithm(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	public static SSLContext getSSLTrustContext(KeyStore trustStore, String trustManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		TrustManager[] trustManagers = getTrustManagers(trustStore, trustManagerAlgorithm);
		return getSSLContext(null, trustManagers, defaultSSLProtocol, sRand);
	}
	
	public static SSLContext getSSLContextWithTrustBypass(KeyStore keyStore, SSLConfig sslConfig) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
		return getSSLContextWithTrustBypass(keyStore, sslConfig.getKeyStorePassword(), sslConfig.getKeyManagerAlgorithm(), sslConfig.getDefaultProtocol(), sslConfig.getSecureRandom());
	}
	
	public static SSLContext getSSLContextWithTrustBypass(KeyStore keyStore, String keyStorePass, String keyManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
		KeyManager[] keyManagers = getKeyManagers(keyStore, keyStorePass, keyManagerAlgorithm);
		return getSSLContext(keyManagers, getTrustManagerBypass(), defaultSSLProtocol, sRand);
	}
	
	public static SSLContext getSSLContext(SSLConfig sslConfig) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, FileNotFoundException, CertificateException, IOException {
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
	
	public static SSLContext getSSLContext(KeyStore keyStore, String keyStorePass, String keyManagerAlgorithm, KeyStore trustStore, String trustManagerAlgorithm, String defaultSSLProtocol, SecureRandom sRand) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
		KeyManager[] keyManagers = getKeyManagers(keyStore, keyStorePass, keyManagerAlgorithm);
		TrustManager[] trustManagers = getTrustManagers(trustStore, trustManagerAlgorithm);
		return getSSLContext(keyManagers, trustManagers, defaultSSLProtocol, sRand);
	}
	
	public static SSLContext getSSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers, String defaultSSLProtocol, SecureRandom sRand) throws NoSuchAlgorithmException, KeyManagementException{
		SecureRandom sRandom = sRand == null ? new SecureRandom() : sRand;
		SSLContext sslContext = SSLContext.getInstance(defaultSSLProtocol);
		sslContext.init(keyManagers, trustManagers, sRandom);
		return sslContext;
	}
	
	public static KeyManager[] getKeyManagers(KeyStore keyStore, String storePass, String keyManagerAlgorithm) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		String algorithm = keyManagerAlgorithm == null ? KeyManagerFactory.getDefaultAlgorithm() : keyManagerAlgorithm;
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
		keyManagerFactory.init(keyStore, storePass.toCharArray());
		return keyManagerFactory.getKeyManagers();
	}
	
	public static TrustManager[] getTrustManagers(KeyStore trustStore, String trustManagerAlgorithm) throws NoSuchAlgorithmException, KeyStoreException {
		String algorithm = trustManagerAlgorithm == null ? TrustManagerFactory.getDefaultAlgorithm() : trustManagerAlgorithm;
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
		trustManagerFactory.init(trustStore);
		return trustManagerFactory.getTrustManagers();
	}
	
	public static X509Certificate loadX509Certificate(File certFile) throws FileNotFoundException, IOException, CertificateException {
		if(certFile == null || !certFile.exists()) {
			return null;
		}
		X509Certificate x509 = null;
		try(FileInputStream inStream = new FileInputStream(certFile)){
			x509 = (X509Certificate) CertificateFactory.getInstance("x509").generateCertificate(inStream);
		}
		return x509;
	}
	
	public static List<X509Certificate> getAllX509Certificates(KeyStore keyStore) throws KeyStoreException {
		if(keyStore == null) {
			return null;
		}
		List<X509Certificate> x509Certs = new ArrayList<>();
		Enumeration<String> aliases = keyStore.aliases();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			Certificate cert = keyStore.getCertificate(alias);
			if(cert instanceof X509Certificate) {
				x509Certs.add((X509Certificate)cert);
			}
		}
		return x509Certs;
	}
	
	public static List<X509Certificate> getX509CertificatesWithAlias(KeyStore keyStore, String findAlias) throws KeyStoreException {
		if(keyStore == null) {
			return null;
		}
		List<X509Certificate> x509Certs = new ArrayList<>();
		Enumeration<String> aliases = keyStore.aliases();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if(findAlias.equals(alias)) {
				Certificate cert = keyStore.getCertificate(alias);
				if(cert instanceof X509Certificate) {
					x509Certs.add((X509Certificate)cert);
				}
			}
		}
		return x509Certs;
	}
	

	
	public static void addAsymmetricKeysToKeyStore(KeyStore store, List<PrivateKeyInfo> privateKeys) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		for(PrivateKeyInfo pkInfo: privateKeys) {
			addAsymmetricKeyToKeyStore(store, pkInfo.certAlias, pkInfo.privateKey, pkInfo.privateKeyPass, pkInfo.certChain);
		}
	}
	
	public static void addAsymmetricKeyToKeyStore(KeyStore store, String certAlias, PrivateKey key, String privateKeyPass, X509Certificate[] certChain) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if(privateKeyPass == null) {
			privateKeyPass = "";
		}
		store.setKeyEntry(certAlias, key, privateKeyPass.toCharArray(), certChain);
	}
	
	public static void addAsymmetricKeysToTrustStore(KeyStore store, List<PublicKeyInfo> publicKeys) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		for(PublicKeyInfo pkInfo: publicKeys) {
			addAsymmetricKeyToTrustStore(store, pkInfo.certAlias, pkInfo.publicKey, pkInfo.certChain);
		}
	}
	
	public static void addAsymmetricKeyToTrustStore(KeyStore store, String certAlias, PublicKey key, X509Certificate[] certChain) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		store.setKeyEntry(certAlias, key.getEncoded(), certChain);
	}
	
	public static void addCertToKeyStore(KeyStore store, String alias, X509Certificate x509) throws KeyStoreException {
		store.setCertificateEntry(alias, x509);
	}
	
	public static void addSymmetricKeyToKeyStore(KeyStore store, String alias, SecretKey secretKey, String secretPass) throws KeyStoreException {
		KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(secretPass.toCharArray());
		store.setEntry(alias, secret, password);
	}
	
	public static TrustManager[] getTrustManagerBypass() {
		X509TrustManager x509TManager = new IgnoreTrustManager();
		return new TrustManager[] { x509TManager };
	}
	
	public static String[] getSSLSupportedCipherSuits() {
		return ((SSLServerSocketFactory)SSLServerSocketFactory.getDefault()).getSupportedCipherSuites();
	}
	
	public static class IgnoreTrustManager implements X509TrustManager {
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			// accept all			
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			// accept all
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}
	
	public static class IgnoreHostnameVerifier implements HostnameVerifier {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	}
	
	public static class PrivateKeyInfo {
		private String certAlias;
		private PrivateKey privateKey;
		private String privateKeyPass;
		private X509Certificate[] certChain;
		
		public PrivateKeyInfo(String certAlias, PrivateKey privateKey, String privateKeyPass, X509Certificate[] certChain) {
			this.certAlias = certAlias;
			this.privateKey = privateKey;
			this.privateKeyPass = privateKeyPass;
			this.certChain = certChain;
		}

		public String getCertAlias() {
			return certAlias;
		}

		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		public String getPrivateKeyPass() {
			return privateKeyPass;
		}

		public X509Certificate[] getCertChain() {
			return certChain;
		}
	}
	
	public static class PublicKeyInfo {
		private String certAlias;
		private PublicKey publicKey;
		private X509Certificate[] certChain;
		
		public PublicKeyInfo(String certAlias, PublicKey publicKey, X509Certificate[] certChain) {
			this.certAlias = certAlias;
			this.publicKey = publicKey;
			this.certChain = certChain;
		}

		public String getCertAlias() {
			return certAlias;
		}

		public PublicKey getPublicKey() {
			return publicKey;
		}

		public X509Certificate[] getCertChain() {
			return certChain;
		}
	}

}
