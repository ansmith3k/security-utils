package org.drop.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * The Class BCUtils.
 */
public class BCUtils {

	/**
	 * Gets the x 500 name.
	 *
	 * @param commonName the common name
	 * @param localityname the localityname
	 * @param stateOrProvinceName the state or province name
	 * @param oranizationName the oranization name
	 * @param organizationUInitName the organization U init name
	 * @param countryName the country name
	 * @param streetAddress the street address
	 * @param domainComponent the domain component
	 * @param userid the userid
	 * @return the x 500 name
	 */
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
	
	/**
	 * Gets the time.
	 *
	 * @param dateTime the date time
	 * @param zoneId the zone id
	 * @return the time
	 */
	public static Time getTime(LocalDateTime dateTime, ZoneId zoneId) {
		return new Time(TimeUtils.getLocalDateTime(dateTime, zoneId));
	}
	
	/**
	 * Write X 509 cert to pem file.
	 *
	 * @param cert the cert
	 * @param file the file
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static void writeX509CertToPemFile(X509Certificate cert, File file) throws IOException {
		try(JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file))){
			writer.writeObject(cert);
		}
	}
	
	/**
	 * Gets the alternative names.
	 *
	 * @param hostnames the hostnames
	 * @param ipAddresses the ip addresses
	 * @return the alternative names
	 */
	public static GeneralNames getAlternativeNames(List<String> hostnames, List<String> ipAddresses) {
		List<GeneralName> altNames = new ArrayList<>();
		if(hostnames != null && !hostnames.isEmpty()) {
			for(String hostname: hostnames) {
				altNames.add(new GeneralName(GeneralName.dNSName, hostname));
			}
		}
		if(ipAddresses != null && !ipAddresses.isEmpty()) {
			for(String addy: hostnames) {
				altNames.add(new GeneralName(GeneralName.iPAddress, addy));
			}
		}
		return GeneralNames.getInstance(new DERSequence((GeneralName[])altNames.toArray(new GeneralName[] {})));
	}
}
