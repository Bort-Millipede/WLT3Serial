/*
	CustomSSLSocketFactory.java
	
	v0.3 (1/18/2018)
	
	Custom implementation of SSLSocketFactory class, intent upon selecting specific SSL/TLS protocol(s) for execution and disabling all SSL/TLS
	certificate validation. Sets enabled SSL/TLS protocol(s) based on the value of System property 'jdk.tls.client.protocols'. Intended to
	override default SSLSocketFactory class in JVM version 7 or lower (as JVM version 8 and higher perform the functions of this custom
	implementation natively by setting System property 'jdk.tls.client.protocols' during runtime). 
	
	Adapted from custom SSLSocketFactory implementation found here: https://gist.github.com/fkrauthan/ac8624466a4dee4fd02f
*/

package bort.millipede.wlt3;

import java.util.ArrayList;
import java.net.Socket;
import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.IOException;

public class CustomSSLSocketFactory extends SSLSocketFactory {
	private SSLSocketFactory defaultSSLSocketFactory;
	
	public CustomSSLSocketFactory() throws Exception {
		super();
		String prot = System.getProperty("jdk.tls.client.protocols");
		if(prot.contains("SSL")) {
			prot = "SSL";
		}
		
		//disable all SSL/TLS certificate validation, and get reference to current system-wide SSLSocketFactory
		SSLContext context = SSLContext.getInstance(prot);
		TrustManager[] trustAll = new TrustManager[] {new TrustAllCertsManager()};
		context.init(null,trustAll,null);
		defaultSSLSocketFactory = context.getSocketFactory();
	}
	
	//set specific SSL/TLS protocol(s) for SSL/TLS-enabled sockets
	private Socket setSSLTLSProtocols(Socket socket) {
		if(socket != null && (socket instanceof SSLSocket)) { //if inputted Socket is an SSL/TLS-enabled Socket: parse enabled protocols and apply
			String tlsSysProp = System.getProperty("jdk.tls.client.protocols");
			ArrayList<String> protocols = new ArrayList<String>(5);
			protocols.add("SSLv2Hello");
			protocols.add("SSLv3");
			protocols.add("TLSv1");
			protocols.add("TLSv1.1");
			protocols.add("TLSv1.2");		
		
			//set enabled SSL/TLS protocol(s) appropriately
			String[] enabledProts = new String[1];
			if(tlsSysProp.contains("SSL")) { //using SSL protocol(s) for connection
				protocols.remove("TLSv1.2");
				protocols.remove("TLSv1.1");
				protocols.remove("TLSv1");
				if(!tlsSysProp.contains("SSLv2Hello")) protocols.remove("SSLv2Hello");
			
				if(protocols.size()>1) {
					enabledProts = new String[] {"SSLv2Hello","SSLv3"};
				} else {
					enabledProts[0] = "SSLv3";
				}
			} else { //using TLS protocol for connection
				protocols.remove("SSLv2Hello");
				protocols.remove("SSLv3");
				if(tlsSysProp.contains("TLSv1.2")) {
					enabledProts[0] = "TLSv1.2";
				} else if(tlsSysProp.contains("TLSv1.1")) {
					enabledProts[0] = "TLSv1.1";
				} else if(tlsSysProp.contains("TLSv1")) {
					enabledProts[0] = "TLSv1";
				}
			}
			
			((SSLSocket) socket).setEnabledProtocols(enabledProts);
        	}
		return socket;
	}
	
	
	//SocketFactory methods
	@Override
	public Socket createSocket() throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket());
	}
	
	@Override
	public Socket createSocket(InetAddress host,int port) throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket(host,port));
	}
	
	@Override
	public Socket createSocket(InetAddress address,int port,InetAddress localAddress,int localPort) throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket(address,port,localAddress,localPort));
	}
	
	@Override
	public Socket createSocket(String host,int port) throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket(host,port));
	}
	
	@Override
	public Socket createSocket(String host,int port,InetAddress localHost,int localPort) throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket(host,port,localHost,localPort));
	}
	
	
	//SSLSocketFactory methods
	@Override
	public Socket createSocket(Socket s,String host,int port,boolean autoClose) throws IOException {
		return setSSLTLSProtocols(defaultSSLSocketFactory.createSocket(s,host,port,autoClose));
	}
	
	@Override
	public String[] getDefaultCipherSuites() {
		return defaultSSLSocketFactory.getDefaultCipherSuites();
	}
	
	@Override
	public String[] getSupportedCipherSuites() {
		return defaultSSLSocketFactory.getSupportedCipherSuites();
	}
}
