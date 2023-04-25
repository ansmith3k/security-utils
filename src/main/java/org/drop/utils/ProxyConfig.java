package org.drop.utils;

public class ProxyConfig {
	private String host;
	private int port;
	private String user;
	private String pass;
	private ProxyType type = ProxyType.HTTP;

	public ProxyConfig(String host, int port) {
		this.host = host;
		this.port = port;
	}
	
	public ProxyConfig(String host, int port, String user) {
		this.host = host;
		this.port = port;
		this.user = user;
	}
	
	public ProxyConfig(String host, int port, String user, String pass) {
		this.host = host;
		this.port = port;
		this.user = user;
		this.pass = pass;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}
	
	public boolean hasUser() {
		return this.user != null;
	}

	public String getPass() {
		return pass;
	}

	public void setPass(String pass) {
		this.pass = pass;
	}
	
	public boolean hasPass() {
		return this.pass != null;
	}

	public ProxyType getType() {
		return type;
	}

	public void setType(ProxyType type) {
		this.type = type;
	}

	public static enum ProxyType{
		HTTP, SOCK5;
	}
}
