/*
	WebServerTestHelper.java
	
	v0.3 (1/18/2018)
	
	Tiny standalone Java web server to aid with JUnit tests. Creates randomly-generated sub-directories, and indicates once they have been accessed by a remote
	host (and what the IP address of the remote host is).
*/

package bort.millipede.wlt3.tests;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.Headers;
import java.net.InetSocketAddress;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.security.SecureRandom;

public class WebServerTestHelper {
	private HttpServer hs;
	private int port;
	private SecureRandom sr;
	private Hashtable<String,String> accessList;
	
	private static final int DEFAULT_PORT = 8080;
	
	public WebServerTestHelper() throws IOException, IllegalArgumentException {
		port = DEFAULT_PORT;
		String inPort = System.getProperty("wlt3.test.server.port");
		if(inPort!=null && !inPort.isEmpty()) {
			try {
				inPort = inPort.trim();
				port = Integer.parseInt(inPort);
				if((port<1) || (port>65535)) {
					throw new IllegalArgumentException("\""+inPort+"\" is not a valid TCP port for standalone web server listener! Valid TCP ports: 0-65535");
				}
			} catch(Exception e) {
				throw new IllegalArgumentException("\""+inPort+"\" is not a valid TCP port for standalone web server listener!");
			}
		}
		
		hs = HttpServer.create(new InetSocketAddress(port),0);
		sr = new SecureRandom();
		accessList = new Hashtable<String,String>();
		
		hs.start();
	}
	
	//dynamically create new context when requested
	public String createContext() {
		String guid = generateGUID();
		hs.createContext("/"+guid,new TestHttpHandler(guid));
		return guid;
	}
	
	public String isSourceAccessed(String path) {
		if(accessList==null) return null;
		return accessList.get(path);
	}
	
	public void stop() {
		hs.stop(0);
		accessList = null;
	}
	
	public int getPort() {
		return port;
	}
	
	private String generateGUID() {
		byte[] buffer = new byte[16];
		sr.nextBytes(buffer);
		String retVal = bytesToHex(buffer);
		return retVal.substring(0,8)+"-"+retVal.substring(8,12)+"-"+retVal.substring(12,16)+"-"+retVal.substring(16,20)+"-"+retVal.substring(20);
	}
	
	private String bytesToHex(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length*2];
		for(int j=0;j<bytes.length;j++){
			int v =bytes[j] & 0xFF;
			hexChars[j*2]=hexArray[v>>>4];
			hexChars[j*2+1]=hexArray[v&0x0F];
		}
		return new String(hexChars);
	}
	
	private class TestHttpHandler implements HttpHandler {
		private String path;
		private boolean accessed;
		private String source;
		
		TestHttpHandler(String p) {
			path = p;
			accessed = false;
			source = null;
		}
		
		public void handle(HttpExchange exchange) {
			try {
				exchange.getRequestMethod();
				exchange.getRequestBody().close();
				Headers respHeaders = null;
				if(!accessed && (source == null)) { //context hasn't been accessed before
					source = exchange.getRemoteAddress().getHostString();
					accessed = true;
					respHeaders = exchange.getResponseHeaders();
					respHeaders.add("Content-Type","text/plain");
					exchange.sendResponseHeaders(200,path.length());
					OutputStream os = exchange.getResponseBody();
					os.write(path.getBytes());
					os.flush();
					os.close();
					accessList.put(path,source);
				} else {
					respHeaders = exchange.getResponseHeaders();
					exchange.sendResponseHeaders(404,0);
					exchange.getResponseBody().close();
				}
			} catch(Exception e) {
				System.err.println("Unforeseen error occurred!");
				e.printStackTrace();
			}
		}
	}	
}

