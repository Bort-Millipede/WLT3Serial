# WLT3Serial
Native Java-based deserialization exploit for WebLogic T3 (and T3S) listeners.

# Usage
Below is the printout of the built-in help menu:

        Usage: WLT3Serial.jar [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD

		Options:
			--help				print usage (you're lookin at it)

			--method=EXPLOIT_METHOD		Method for delivering ysoserial payload:
				Exploit Methods:
					Property	Send ysoserial payload as connection environment property value (Default, similar to JavaUnserializeExploits weblogic.py)
					Bind		Send ysoserial payload as object to bind to name (via javax.naming.Context.bind())
					WLBind		Send ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)

			--t3s[=PROTOCOL]		Use T3S (transport-encrypted) connection (Disabled by default)
				Protocols:
					TLSv1.2 (Default)
					TLSv1.1
					TLSv1
					(Note: SSLv2 and SSLv3 are unsupported at this time.)

# Development
Tested against the following versions of WebLogic Server:

	*10.3.6.0
	*12.1.3
	*12.2.1.1 (may not be vulnerable)
	*12.2.1.2 (may not be vulnerable)
	*12.2.1.3 (not vulnerable)

# Building
Coming Soon!
