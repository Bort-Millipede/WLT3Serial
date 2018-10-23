/*
	WLT3SerialHelper.java
	
	v0.4 (10/23/2018)
	
	Helper class containing static methods to be used throughout WLT3Serial (in the bort.millipede.wlt3 package).
*/

package bort.millipede.wlt3;

import java.lang.reflect.Method;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

class WLT3SerialHelper {
	//Set SSL/TLS options: enable desired protocol(s) and disable protocols not chosen during application startup
	static void setSSLTLSProtocol() throws Exception {
		String tlsSysProp = System.getProperty("jdk.tls.client.protocols");

		//check if 'jdk.tls.disabledAlgorithms' Security property is set, and remove SSLv3 if set
		String tlsSecProp = Security.getProperty("jdk.tls.disabledAlgorithms");
		if(tlsSecProp!=null) {
			ArrayList<String> protocols = new ArrayList<String>(5);
			protocols.add("SSLv2Hello");
			protocols.add("SSLv3");
			protocols.add("TLSv1");
			protocols.add("TLSv1.1");
			protocols.add("TLSv1.2");
			
			String disabledProts = null;
			if(tlsSysProp.contains("SSL")) { //using SSL protocol(s) for connection
				protocols.remove("SSLv3");
				if(tlsSysProp.contains("SSLv2Hello")) protocols.remove("SSLv2Hello");
				disabledProts = join(protocols,", ");
		
				if(tlsSecProp.contains("SSLv3")) {
					tlsSecProp = tlsSecProp.replace("SSLv3", disabledProts);
				} else {
					tlsSecProp = tlsSecProp.trim();
					if(!tlsSecProp.isEmpty()) tlsSecProp += ", ";
					tlsSecProp += disabledProts;
				}
			} else { //using TLS protocol for connection
				switch(tlsSysProp) {
					case "TLSv1.2":
						protocols.remove("TLSv1.2");
						break;
					case "TLSv1.1":
						protocols.remove("TLSv1.1");
						break;
					case "TLSv1":
						protocols.remove("TLSv1");
						break;
				}
				
				if(!tlsSecProp.isEmpty()) tlsSecProp += ", ";
				tlsSecProp += join(protocols,", ");
			}
			Security.setProperty("jdk.tls.disabledAlgorithms",tlsSecProp);
		} else { //jdk.tls.disabledAlgorithms is not set in running JVM: if JVM is version 8, set property
			if(!isJVM7()) {
				ArrayList<String> protocols = new ArrayList<String>(5);
				protocols.add("SSLv2Hello");
				protocols.add("SSLv3");
				protocols.add("TLSv1");
				protocols.add("TLSv1.1");
				protocols.add("TLSv1.2");
				
				String disabledProts = null;
				if(tlsSysProp.contains("SSL")) { //using SSL protocol(s) for connection
					protocols.remove("SSLv3");
					if(tlsSysProp.contains("SSLv2Hello")) protocols.remove("SSLv2Hello");
					disabledProts = join(protocols,", ");
			
					if(tlsSecProp.contains("SSLv3")) {
						tlsSecProp = tlsSecProp.replace("SSLv3", disabledProts);
					} else {
						tlsSecProp = tlsSecProp.trim();
						if(!tlsSecProp.isEmpty()) tlsSecProp += ", ";
						tlsSecProp += disabledProts;
					}
				} else { //using TLS protocol for connection
					switch(tlsSysProp) {
						case "TLSv1.2":
							protocols.remove("TLSv1.2");
							break;
						case "TLSv1.1":
							protocols.remove("TLSv1.1");
							break;
						case "TLSv1":
							protocols.remove("TLSv1");
							break;
					}
					
					if(!tlsSecProp.isEmpty()) tlsSecProp += ", ";
					tlsSecProp += join(protocols,", ");
				}
				Security.setProperty("jdk.tls.disabledAlgorithms",tlsSecProp);
			}
		}
		
		if(isJVM7()) { //running JVM is version 7 or lower: set custom SSLSocketFactory implementation as default
			Security.setProperty("ssl.SocketFactory.provider","bort.millipede.wlt3.CustomSSLSocketFactory");
		} else { //running JVM is version 8 or higher: set default SSLContext with SSL/TLS certificate validation disabled
			SSLContext defaultContext = null;
			if(tlsSysProp.contains("SSL")) {
				defaultContext = SSLContext.getInstance("SSL");
			} else {
				defaultContext = SSLContext.getInstance(tlsSysProp);
			}
			TrustManager[] trustAll = new TrustManager[] {new TrustAllCertsManager()};
			defaultContext.init(null,trustAll,null);
			SSLContext.setDefault(defaultContext);
		}
	}
	
	//join List<String> into String with specified delimeter
	static String join(List<String> list,String delimeter) {
		if(delimeter==null) delimeter="";
		if(list==null) return null;
		
		String[] arr = new String[list.size()];
		arr = list.toArray(arr);
		String retVal = "";
		int i=0;
		while(i<arr.length-1) {
			if(arr[i]==null) arr[i] = "";
			retVal += arr[i]+delimeter;
			i++;
		}
		if(arr[i]==null) arr[i] = "";
		retVal += arr[i];
		return retVal;
	}
	
	//check if running JVM is Java 7
	static boolean isJVM7() {
		return (Double.parseDouble(System.getProperty("java.vm.specification.version")) < 1.8);
	}
	
	//check if weblogic.rjvm.ClassTableEntry class loaded into JVM is default or custom implementation
	static boolean isCTECustom() {
		try {
			Class<?> cteClass = Class.forName("weblogic.rjvm.ClassTableEntry");
			Method m = cteClass.getDeclaredMethod("isCTECustom");
			return true;
		} catch(ClassNotFoundException cnfe) {
			//should never happen, and error will be handled elsewhere in WLT3Serial class
		} catch(NoSuchMethodException nsme) {
			//method does not exist: do nothing so method will return false
		}
		return false;
	}
}

