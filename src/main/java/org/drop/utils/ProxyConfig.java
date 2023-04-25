package org.drop.utils;

// TODO: Auto-generated Javadoc
/**
 * The Class ProxyConfig.
 */
public class ProxyConfig {
	
	/** The host. */
	private String host;
	
	/** The port. */
	private int port;
	
	/** The user. */
	private String user;
	
	/** The pass. */
	private String pass;
	
	/** The type. */
	private ProxyType type = ProxyType.HTTP;

	/**
	 * Instantiates a new proxy config.
	 *
	 * @param host the host
	 * @param port the port
	 */
	public ProxyConfig(String host, int port) {
		this.host = host;
		this.port = port;
	}
	
	/**
	 * Instantiates a new proxy config.
	 *
	 * @param host the host
	 * @param port the port
	 * @param user the user
	 */
	public ProxyConfig(String host, int port, String user) {
		this.host = host;
		this.port = port;
		this.user = user;
	}
	
	/**
	 * Instantiates a new proxy config.
	 *
	 * @param host the host
	 * @param port the port
	 * @param user the user
	 * @param pass the pass
	 */
	public ProxyConfig(String host, int port, String user, String pass) {
		this.host = host;
		this.port = port;
		this.user = user;
		this.pass = pass;
	}

	/**
	 * Gets the host.
	 *
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * Sets the host.
	 *
	 * @param host the new host
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * Gets the port.
	 *
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Sets the port.
	 *
	 * @param port the new port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * Gets the user.
	 *
	 * @return the user
	 */
	public String getUser() {
		return user;
	}

	/**
	 * Sets the user.
	 *
	 * @param user the new user
	 */
	public void setUser(String user) {
		this.user = user;
	}
	
	/**
	 * Checks for user.
	 *
	 * @return true, if successful
	 */
	public boolean hasUser() {
		return this.user != null;
	}

	/**
	 * Gets the pass.
	 *
	 * @return the pass
	 */
	public String getPass() {
		return pass;
	}

	/**
	 * Sets the pass.
	 *
	 * @param pass the new pass
	 */
	public void setPass(String pass) {
		this.pass = pass;
	}
	
	/**
	 * Checks for pass.
	 *
	 * @return true, if successful
	 */
	public boolean hasPass() {
		return this.pass != null;
	}

	/**
	 * Gets the type.
	 *
	 * @return the type
	 */
	public ProxyType getType() {
		return type;
	}

	/**
	 * Sets the type.
	 *
	 * @param type the new type
	 */
	public void setType(ProxyType type) {
		this.type = type;
	}

	/**
	 * The Enum ProxyType.
	 */
	public static enum ProxyType{
		
		/** The http. */
		HTTP, 
 /** The sock5. */
 SOCK5;
	}
}
