/*
	TrustAllCertsManager.java
	
	v0.2 (12/2/2017)
	
	Class intended to override the default SSL/TLS trust manager to trust all certificates.
*/

package bort.millipede.wlt3;

import java.net.Socket;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

class TrustAllCertsManager extends X509ExtendedTrustManager {
	TrustAllCertsManager() {
		
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain,String authType) {
		//empty: trust all client certificates
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
		//empty: trust all client certificats
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
		//empty: trust all client certificats
	}
	
	@Override
	public void checkServerTrusted(X509Certificate[] chain,String authType) {
		//empty: trust all server certificates
	}
	
	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
		//empty: trust all server certificats
	}
	
	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
		//empty: trust all server certificats
	}
	
	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return null; //empty: accept all issuers
	}
}

