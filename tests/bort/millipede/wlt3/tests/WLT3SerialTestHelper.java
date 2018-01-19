/*
	WLT3SerialTestHelper.java
	
	v0.3 (1/18/2018)
	
	Helper class containing static helper methods to be leveraged by the various WLT3Serial JUnit tests.
*/

package bort.millipede.wlt3.tests;

import bort.millipede.wlt3.WLT3Serial;
import org.junit.Assert;

public class WLT3SerialTestHelper {
	//check input properties 'wlt3.target.host', 'wlt3.target.t3.port' and 'wlt3.target.t3s.port'.
	public static void checkTargetParams() {
		String strPort = System.getProperty("wlt3.target.t3.port");
		String strPort2 = System.getProperty("wlt3.target.t3s.port");
		Assert.assertNotNull("System property \"wlt3.target.host\" not set!",System.getProperty("wlt3.target.host"));
		Assert.assertNotNull("System property \"wlt3.target.t3.port\" not set!",strPort);
		Assert.assertNotNull("System property \"wlt3.target.t3s.port\" not set!",strPort2);
		int port = -1;
		try {
			port = Integer.parseInt(strPort);
			if((port<0) && (port>65535)) {
				throw new AssertionError("Provided T3 port "+strPort+" is not a valid TCP port! Valid TCP ports: 0-65535");
			}
		} catch (Exception e) {
			throw new AssertionError("Provided T3 port \""+strPort+"\" is not a valid TCP port!");
		}
		port = -1;
		try {
			port = Integer.parseInt(strPort2);
			if((port<0) && (port>65535)) {
				throw new AssertionError("Provided T3S port "+strPort2+" is not a valid TCP port! Valid TCP ports: 0-65535");
			}
		} catch (Exception e) {
			throw new AssertionError("Provided T3 port \""+strPort2+"\" is not a valid TCP port!");
		}
	}
	
	//execute WLT3Serial main method in order to run exploit against target system. checkTargetParams() must be executed before executing runExploit().
	public static void runExploit(String t3s,String method,String cmd) {
		String host = System.getProperty("wlt3.target.host");
		String port = System.getProperty("wlt3.target.t3.port");
		String t3sPort = System.getProperty("wlt3.target.t3s.port");
		boolean verbose = false;
		String strVerbose = System.getProperty("wlt3.test.verbose");
		if(strVerbose != null) verbose = Boolean.parseBoolean(strVerbose);
		
		//attempt to run exploit
		String[] args = null;
		if(verbose) {
			if(t3s != null && !t3s.isEmpty()) {
				args = new String[] {"--verbose",t3s,host,t3sPort,method,cmd};
			} else {
				args = new String[] {"--verbose",host,port,method,cmd};
			}
		} else {
			if(t3s != null && !t3s.isEmpty()) {
				args = new String[] {t3s,host,t3sPort,method,cmd};
			} else {
				args = new String[] {host,port,method,cmd};
			}
		}
		WLT3Serial.main(args);
	}
	
	//check inputted WebServerTestHelper object for access from remote host
	public static String getAccessedHost(WebServerTestHelper ws,String path) {
		int i=0;
		String strNumTries = System.getProperty("wlt3.test.tries");
		int numTries = 5;
		if(strNumTries != null) {
			try {
				numTries = Integer.parseInt(strNumTries);
			} catch(Exception e) {
				throw new IllegalArgumentException("Provided wlt3.test.tries property \""+strNumTries+"\" is not a valid integer");
			}
		}
		String remoteIP = null;
		while((remoteIP == null) && (i<numTries)) {
			remoteIP = ws.isSourceAccessed(path);
			i+=1;
			try {
				Thread.sleep(1000);
			} catch(Exception e) {
				//don't care
			}
		}
		return remoteIP;
	}
	
	//check whether remote (IP) retrieved earlier from WebServerTestHelper object matches current local IP address.
	public static void checkAccessedHost(String remoteIP) {
		String host = System.getProperty("wlt3.target.host");
		if(remoteIP == null) {
			throw new AssertionError("Embedded web server was not accessed by target server "+host+"!");
		} else {
			Assert.assertEquals("Embedded web server was not accessed by target server "+host+" (was accessed by different remote host "+remoteIP+")!",host,remoteIP);
		}
	}
}
