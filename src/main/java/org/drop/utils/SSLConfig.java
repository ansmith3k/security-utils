package org.drop.utils;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

// TODO: Auto-generated Javadoc
/**
 * The Class SSLConfig.
 */
public class SSLConfig {

	/** The Constant DEFAULT_SSL_CIPHERS. */
	private static final String DEFAULT_SSL_CIPHERS = "TLS_RSA_WITH_AES_256_GCM_SHA384";
	
	/** The Constant DEFAULT_STORE_TYPE. */
	private static final String DEFAULT_STORE_TYPE = "pkcs12";
	
	/** The Constant DEFAULT_SSL_PROTOCOL. */
	private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";
	
	/** The enabled. */
	private boolean enabled = false;
	
	/** The key store file. */
	private String keyStoreFile;
	
	/** The key store password. */
	private String keyStorePassword;
	
	/** The key store type. */
	private String keyStoreType = DEFAULT_STORE_TYPE;
	
	/** The trust store file. */
	private String trustStoreFile;
	
	/** The trust store password. */
	private String trustStorePassword;
	
	/** The trust store type. */
	private String trustStoreType = DEFAULT_STORE_TYPE;
	
	/** The trust all certs. */
	private boolean trustAllCerts = false;
	
	/** The trust all hostnames. */
	private boolean trustAllHostnames = false;
	
	/** The default protocol. */
	private String defaultProtocol = DEFAULT_SSL_PROTOCOL;
	
	/** The enabled protocols. */
	private Set<String> enabledProtocols = new HashSet<>();
	
	/** The enabled ciphers. */
	private Set<String> enabledCiphers = new HashSet<>();
	
	/** The secure random. */
	private SecureRandom secureRandom = null;
	
	/** The key manager algorithm. */
	private String keyManagerAlgorithm = null;
	
	/** The trust manager algorithm. */
	private String trustManagerAlgorithm = null;
	
	private HostnameVerifier hostnameVerifier = null;
	
	/**
	 * Instantiates a new SSL config.
	 */
	public SSLConfig() {
		keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	}
	
	/**
	 * Checks if is enabled.
	 *
	 * @return true, if is enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}
	
	/**
	 * Sets the enabled.
	 *
	 * @param enabled the new enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	/**
	 * Gets the key store file.
	 *
	 * @return the key store file
	 */
	public String getKeyStoreFile() {
		return keyStoreFile;
	}
	
	/**
	 * Sets the key store file.
	 *
	 * @param keyStoreFile the new key store file
	 */
	public void setKeyStoreFile(String keyStoreFile) {
		this.keyStoreFile = keyStoreFile;
	}
	
	/**
	 * Gets the key store password.
	 *
	 * @return the key store password
	 */
	public String getKeyStorePassword() {
		return keyStorePassword;
	}
	
	/**
	 * Sets the key store password.
	 *
	 * @param keyStorePassword the new key store password
	 */
	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}
	
	/**
	 * Gets the key store type.
	 *
	 * @return the key store type
	 */
	public String getKeyStoreType() {
		return keyStoreType;
	}
	
	/**
	 * Sets the key store type.
	 *
	 * @param keyStoreType the new key store type
	 */
	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}
	
	/**
	 * Checks for key store.
	 *
	 * @return true, if successful
	 */
	public boolean hasKeyStore() {
		return keyStoreFile != null && keyStorePassword != null;
	}
	
	/**
	 * Gets the trust store file.
	 *
	 * @return the trust store file
	 */
	public String getTrustStoreFile() {
		return trustStoreFile;
	}
	
	/**
	 * Sets the trust store file.
	 *
	 * @param trustStoreFile the new trust store file
	 */
	public void setTrustStoreFile(String trustStoreFile) {
		this.trustStoreFile = trustStoreFile;
	}
	
	/**
	 * Gets the trust store password.
	 *
	 * @return the trust store password
	 */
	public String getTrustStorePassword() {
		return trustStorePassword;
	}
	
	/**
	 * Sets the trust store password.
	 *
	 * @param trustStorePassword the new trust store password
	 */
	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}
	
	/**
	 * Gets the trust store type.
	 *
	 * @return the trust store type
	 */
	public String getTrustStoreType() {
		return trustStoreType;
	}
	
	/**
	 * Sets the trust store type.
	 *
	 * @param trustStoreType the new trust store type
	 */
	public void setTrustStoreType(String trustStoreType) {
		this.trustStoreType = trustStoreType;
	}
	
	/**
	 * Checks if is trust all certs.
	 *
	 * @return true, if is trust all certs
	 */
	public boolean isTrustAllCerts() {
		return trustAllCerts;
	}
	
	/**
	 * Sets the trust all certs.
	 *
	 * @param trustAllCerts the new trust all certs
	 */
	public void setTrustAllCerts(boolean trustAllCerts) {
		this.trustAllCerts = trustAllCerts;
	}
	
	/**
	 * Checks if is trust all hostnames.
	 *
	 * @return true, if is trust all hostnames
	 */
	public boolean isTrustAllHostnames() {
		return trustAllHostnames;
	}
	
	/**
	 * Sets the trust all hostnames.
	 *
	 * @param trustAllHostnames the new trust all hostnames
	 */
	public void setTrustAllHostnames(boolean trustAllHostnames) {
		this.trustAllHostnames = trustAllHostnames;
	}
	
	/**
	 * Gets the default protocol.
	 *
	 * @return the default protocol
	 */
	public String getDefaultProtocol() {
		return defaultProtocol;
	}
	
	/**
	 * Sets the default protocol.
	 *
	 * @param defaultProtocol the new default protocol
	 */
	public void setDefaultProtocol(String defaultProtocol) {
		this.defaultProtocol = defaultProtocol;
	}
	
	/**
	 * Gets the protocols.
	 *
	 * @return the protocols
	 */
	public Set<String> getProtocols() {
		return enabledProtocols;
	}
	
	/**
	 * Sets the protocols.
	 *
	 * @param protocols the new protocols
	 */
	public void setProtocols(Set<String> protocols) {
		this.enabledProtocols = protocols;
	}
	
	/**
	 * Adds the protocols.
	 *
	 * @param protocol the protocol
	 */
	public void addProtocols(String protocol) {
		this.enabledProtocols.add(protocol);
	}
	
	/**
	 * Gets the ciphers.
	 *
	 * @return the ciphers
	 */
	public Set<String> getCiphers() {
		return enabledCiphers;
	}
	
	/**
	 * Sets the ciphers.
	 *
	 * @param ciphers the new ciphers
	 */
	public void setCiphers(Set<String> ciphers) {
		this.enabledCiphers = ciphers;
	}
	
	/**
	 * Adds the cipher.
	 *
	 * @param cipher the cipher
	 */
	public void addCipher(String cipher) {
		this.enabledCiphers.add(cipher);
	}
	
	/**
	 * Gets the secure random.
	 *
	 * @return the secure random
	 */
	public SecureRandom getSecureRandom() {
		return secureRandom == null ? new SecureRandom() : secureRandom;
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
	 * Gets the key manager algorithm.
	 *
	 * @return the key manager algorithm
	 */
	public String getKeyManagerAlgorithm() {
		return keyManagerAlgorithm;
	}

	/**
	 * Sets the key manager algorithm.
	 *
	 * @param keyManagerAlgorithm the new key manager algorithm
	 */
	public void setKeyManagerAlgorithm(String keyManagerAlgorithm) {
		this.keyManagerAlgorithm = keyManagerAlgorithm;
	}

	/**
	 * Gets the trust manager algorithm.
	 *
	 * @return the trust manager algorithm
	 */
	public String getTrustManagerAlgorithm() {
		return trustManagerAlgorithm;
	}

	/**
	 * Sets the trust manager algorithm.
	 *
	 * @param trustManagerAlgorithm the new trust manager algorithm
	 */
	public void setTrustManagerAlgorithm(String trustManagerAlgorithm) {
		this.trustManagerAlgorithm = trustManagerAlgorithm;
	}

	public HostnameVerifier getHostnameVerifier() {
		return hostnameVerifier;
	}

	public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
		this.hostnameVerifier = hostnameVerifier;
	}
}

