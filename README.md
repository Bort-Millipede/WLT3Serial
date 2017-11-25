# WLT3Serial
Native Java-based deserialization exploit for WebLogic T3 (and T3S) listeners.

# Advantages/Disadvantages compared to JavaUnserializeExploits weblogic.py and loubia
## Advantages:
* Handles T3/T3S communication natively instead of using packet captures, and therefore should work in all cases.
* Generates object payloads directly through ysoserial during every execution, and therefore should work in most cases.

## Disadvantages:
* Depends on .jar file that cannot be distributed by me (due to Oracle Licensing terms) and can only be download with an Oracle username/password.
* For T3S, SSLv2 and SSLv3 communication is not supported.
* SSL/TLS certificate validation is enabled, so T3S connections require the use of InstallCert (https://github.com/escline/InstallCert) in order to connect and run properly.

# Usage
Below is the printout of the built-in help menu:

		Usage: WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD
	
		Options:
			--help				print usage (you're lookin at it)

			--verbose			Verbose output (including full thrown exceptions) (NOT YET IMPLEMENTED)

			--method=EXPLOIT_METHOD		Exploit Method for delivering generated ysoserial payload
				Exploit Methods:
					Property	Send ysoserial payload as connection environment property value (Default, javax.naming.Context.lookup(), similar to JavaUnserializeExploits weblogic.py)
					Bind		Send ysoserial payload as object to bind to name (via javax.naming.Context.bind(), also similar to JavaUnserializeExploits weblogic.py)
					WLBind		Send ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)

			--t3s[=PROTOCOL]		Use T3S (transport-encrypted) connection (Disabled by default)
				Protocols:
					TLSv1.2 (Default)
					TLSv1.1
					TLSv1
					(Note: SSLv2 and SSLv3 are unsupported at this time.)
		
		
		Available Payload Types (WebLogic is usually vulnerable to "CommonsCollectionsX" types):
			(available payloads listed here)

# Development
Tested against the following versions of WebLogic Server:

* 10.3.6.0
* 12.1.3
* 12.2.1.1 (may not be vulnerable)
* 12.2.1.2 (may not be vulnerable)
* 12.2.1.3 (not vulnerable)

# Building
Coming Soon!
