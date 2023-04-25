package org.drop.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class BCUtils {

	public static X500Name getX500Name(String commonName, String localityname, String stateOrProvinceName,
			String oranizationName, String organizationUInitName, String countryName, String streetAddress,
			String domainComponent, String userid) {
		StringBuilder str = new StringBuilder();
		if(commonName != null) {
			str.append("CN=").append(commonName).append(", ");
		}
		if(commonName != null) {
			str.append("L=").append(localityname).append(", ");
		}
		if(commonName != null) {
			str.append("ST=").append(stateOrProvinceName).append(", ");
		}
		if(commonName != null) {
			str.append("O=").append(oranizationName).append(", ");
		}
		if(commonName != null) {
			str.append("OU=").append(organizationUInitName).append(", ");
		}
		if(commonName != null) {
			str.append("C=").append(countryName).append(", ");
		}
		if(commonName != null) {
			str.append("STREET=").append(streetAddress).append(", ");
		}
		if(commonName != null) {
			str.append("DC=").append(domainComponent).append(", ");
		}
		if(commonName != null) {
			str.append("UID=").append(userid).append(", ");
		}
		return new X500Name(str.substring(0, str.length()-2));
	}
	
	public static Time getTime(LocalDateTime dateTime, ZoneId zoneId) {
		return new Time(TimeUtils.getLocalDateTime(dateTime, zoneId));
	}
	
	public static void writeX509CertToPemFile(X509Certificate cert, File file) throws IOException {
		try(JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file))){
			writer.writeObject(cert);
		}
	}
}
