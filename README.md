# WLT3Serial
Native Java-based deserialization exploit for WebLogic T3 (and T3S) listeners (as outlined [HERE](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#weblogic "What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.")). Requires third-party dependencies ysoserial and wlthint3client.

## Advantages/Disadvantages compared to [JavaUnserializeExploits weblogic.py](https://github.com/breenmachine/JavaUnserializeExploits/blob/master/weblogic.py) and [loubia](https://github.com/metalnas/loubia)
### Advantages:
* Handles T3/T3S communication natively with Java instead of using packet captures with Python, and therefore should work against all WebLogic server versions.
* Generates object payloads directly through ysoserial during every execution, and therefore supports the latest ysoserial version for payload generation.
* Parses (and displays if requested) all thrown Exceptions during execution, and clearly states the overall result of execution based off these Exceptions. This includes notifying the user if exploitation appears to be successful, or if the target WebLogic server appears to be patched against exploitation.
* Offers several different methods for payload delivery (although all are similar, and chances are all work against an unpatched WebLogic server and all do not work against a patched WebLogic server).

### Disadvantages:
* Depends on a .jar file (wlthint3client.jar) that cannot be distributed by me (due to Oracle Licensing terms) and can only be downloaded with an Oracle username/password. Because of this, I can only distribute a "thin" release jar that still requires the user to obtain the required wlthint3client.jar file from Oracle.
* For T3S connections, SSLv2 and SSLv3 communication is not supported. __(NOTE: SSLv2 and SSLv3 support in progress, to be incorporated in next release)__
* SSL/TLS certificate validation is enabled by default in Java, so T3S connections require the use of [InstallCert](https://github.com/escline/InstallCert) in order to connect and run properly. __(NOTE: Fix in progress, to be incorporated in next release)__

# Building
Requires Java 8 or above. Has not been tested with any other Java versions.

WLT3Serial is built via the Gradle build automation system (https://gradle.org/)

Third-Party Dependencies:

* ysoserial - For generating object deserialization payloads (https://github.com/frohoff/ysoserial, will be downloaded automatically by Gradle if not provided in advance by user.)
* wlthint3client - For handling T3/T3S connections natively, must be supplied by the user (due to Oracle Licensing terms); Can be downloaded (requires Oracle username/password) as part of [wls1036_dev.zip](http://download.oracle.com/otn/nt/middleware/11g/wls/1036/wls1036_dev.zip) (located in /wlserver/server/lib/wlthint3client.jar).

Procedure:

1. Clone the WLT3Serial repository. ```git clone https://github.com/Bort-Millipede/WLT3Serial.git```
2. Open terminal and navigate to cloned repository.
3. Execute the following command to create the preliminary build directory: ```gradle clean prepare```
4. Place downloaded wlthint3client.jar file in the build/libs/ directory.
5. (OPTIONAL) If using a preferred version of ysoserial, place the ysoserial.jar file in the build/libs/ directory.
6. To build a "thin" executable WLT3Serial jar file (located at build/libs/WLT3Serial-[VERSION].jar), execute the following command: ```gradle build```
7. To build a full all-in-one executable WLT3Serial jar file (located at build/libs/WLT3Serial-full-[VERSION].jar), execute the following command: ```gradle fatJar```


# Usage
Requires Java 8 or higher. Will likely work with Java 7 (at the lowest), but T3S connections may not be handled properly under Java 7. Therefore I make no promises of this working with anything lower than Java 8.

If using the "thin" jar, WLT3Serial should be executed as such:

* on *nix: ```java -cp /path/to/wlthint3client.jar:/path/to/ysoserial.jar:/path/to/WLT3Serial-[VERSION].jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```
* on Windows: ```java -cp \path\to\wlthint3client.jar;\path\to\ysoserial.jar;\path\to\WLT3Serial-[VERSION].jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```

If using the full all-in-one executable, WLT3Serial should be executed as such: ```java -jar WLT3Serial-full-[VERSION].jar [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```

Below is the printout of the built-in help menu:

```shell
Usage: WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD

Options:
	--help				print usage (you're lookin at it)

	--verbose			Verbose output (full thrown exception output)

	--method=EXPLOIT_METHOD		Exploit Method for delivering generated ysoserial payload
		Exploit Methods:
			Property	Send ysoserial payload as connection environment property value (Default, via javax.naming.Context.lookup(), similar to JavaUnserializeExploits weblogic.py)
			Bind		Send ysoserial payload as object to bind to name (via javax.naming.Context.bind(), also similar to JavaUnserializeExploits weblogic.py)
			WLBind		Send ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)

	--t3s[=PROTOCOL]		Use T3S (transport-encrypted) connection (Disabled by default)
		Protocols:
			TLSv1.2 (Default)
			TLSv1.1
			TLSv1
			SSLv3
			SSLv2
			(Note: "SSLv2" protocol option only performs initial handshake with SSLv2Hello, then uses SSLv3 for communication: this is a Java limitation)


Available Payload Types (WebLogic is usually vulnerable to "CommonsCollectionsX" types):
	(available payloads listed here)
```

### T3S Connection Notes
it is recommended that the user does a scan of the target service with [sslscan](https://github.com/rbsec/sslscan) or the [nmap ssl-enum-ciphers](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html) script to find out which protocols are supported. This way, the user can fine-tune the --t3s option when executing WLT3Serial.

# Development
In an attempt to improve upon the [JavaUnserializeExploits weblogic.py](https://github.com/breenmachine/JavaUnserializeExploits/blob/master/weblogic.py) and [loubia](https://github.com/metalnas/loubia) exploits, WLT3Serial was developed in Java using the following resources for connecting to WebLogic T3/T3S services:

* https://docs.oracle.com/cd/E21764_01/web.1111/e13717/wlthint3client.htm
* https://docs.oracle.com/cd/E13222_01/wls/docs92/jndi/jndi.html
* https://docs.oracle.com/cd/E11035_01/wls100/javadocs/weblogic/rmi/Naming.html

Emphasis was placed on handling T3 connections natively in Java, as well as proper error handling to provide helpful command output for the user.

During development, WLT3Serial was tested against the following versions of WebLogic Server:

* 10.3.6
* 12.1.3
* 12.2.1.1 (may not be vulnerable)
* 12.2.1.2 (may not be vulnerable)
* 12.2.1.3 (not vulnerable)

Copyright (C) 2017 Jeffrey Cap (Bort_Millipede)

