package org.drop.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class SSLConfig {

	private static final String DEFAULT_SSL_CIPHERS = "TLS_RSA_WITH_AES_256_GCM_SHA384";
	private static final String DEFAULT_STORE_TYPE = "pkcs12";
	private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";
	private boolean enabled = false;
	private String keyStoreFile;
	private String keyStorePassword;
	private String keyStoreType = DEFAULT_STORE_TYPE;
	private String trustStoreFile;
	private String trustStorePassword;
	private String trustStoreType = DEFAULT_STORE_TYPE;
	private boolean trustAllCerts = false;
	private boolean trustAllHostnames = false;
	private String defaultProtocol = DEFAULT_SSL_PROTOCOL;
	private Set<String> enabledProtocols = new HashSet<>();
	private Set<String> enabledCiphers = new HashSet<>();
	private SecureRandom secureRandom = null;
	private String keyManagerAlgorithm = null;
	private String trustManagerAlgorithm = null;
	
	public SSLConfig() {
		keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	}
	
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public String getKeyStoreFile() {
		return keyStoreFile;
	}
	public void setKeyStoreFile(String keyStoreFile) {
		this.keyStoreFile = keyStoreFile;
	}
	public String getKeyStorePassword() {
		return keyStorePassword;
	}
	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}
	public String getKeyStoreType() {
		return keyStoreType;
	}
	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}
	public boolean hasKeyStore() {
		return keyStoreFile != null && keyStorePassword != null;
	}
	public String getTrustStoreFile() {
		return trustStoreFile;
	}
	public void setTrustStoreFile(String trustStoreFile) {
		this.trustStoreFile = trustStoreFile;
	}
	public String getTrustStorePassword() {
		return trustStorePassword;
	}
	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}
	public String getTrustStoreType() {
		return trustStoreType;
	}
	public void setTrustStoreType(String trustStoreType) {
		this.trustStoreType = trustStoreType;
	}
	public boolean isTrustAllCerts() {
		return trustAllCerts;
	}
	public void setTrustAllCerts(boolean trustAllCerts) {
		this.trustAllCerts = trustAllCerts;
	}
	public boolean isTrustAllHostnames() {
		return trustAllHostnames;
	}
	public void setTrustAllHostnames(boolean trustAllHostnames) {
		this.trustAllHostnames = trustAllHostnames;
	}
	public String getDefaultProtocol() {
		return defaultProtocol;
	}
	public void setDefaultProtocol(String defaultProtocol) {
		this.defaultProtocol = defaultProtocol;
	}
	public Set<String> getProtocols() {
		return enabledProtocols;
	}
	public void setProtocols(Set<String> protocols) {
		this.enabledProtocols = protocols;
	}
	public void addProtocols(String protocol) {
		this.enabledProtocols.add(protocol);
	}
	public Set<String> getCiphers() {
		return enabledCiphers;
	}
	public void setCiphers(Set<String> ciphers) {
		this.enabledCiphers = ciphers;
	}
	public void addCipher(String cipher) {
		this.enabledCiphers.add(cipher);
	}
	public SecureRandom getSecureRandom() {
		return secureRandom == null ? new SecureRandom() : secureRandom;
	}
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	public String getKeyManagerAlgorithm() {
		return keyManagerAlgorithm;
	}

	public void setKeyManagerAlgorithm(String keyManagerAlgorithm) {
		this.keyManagerAlgorithm = keyManagerAlgorithm;
	}

	public String getTrustManagerAlgorithm() {
		return trustManagerAlgorithm;
	}

	public void setTrustManagerAlgorithm(String trustManagerAlgorithm) {
		this.trustManagerAlgorithm = trustManagerAlgorithm;
	}
}

