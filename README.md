# WLT3Serial
Native Java-based deserialization exploit for WebLogic T3 (and T3S) listeners (as outlined [HERE](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#weblogic "What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.")). Requires third-party dependencies ysoserial and wlthint3client.

## Advantages/Disadvantages compared to [JavaUnserializeExploits weblogic.py](https://github.com/breenmachine/JavaUnserializeExploits/blob/master/weblogic.py) and [loubia](https://github.com/metalnas/loubia)
### Advantages:
* Handles T3/T3S communication natively (for most exploitation methods) with Java instead of using one-time packet captures with Python scripts, and therefore should work against all WebLogic server versions.
* Generates object payloads directly through ysoserial during every execution instead of one-time-generated object payloads, and therefore supports all object payload types in the latest ysoserial version.
* Parses (and displays if requested) all thrown Exceptions during execution, and clearly states the assumed overall result of execution based off these Exceptions. This includes notifying the user if exploitation appears to be successful, if SSL/TLS-enabled communication failed, or if the target WebLogic server appears to be patched against exploitation.
* Offers several different methods for payload delivery (similar to both JavaUnserialize weblogic.py/loubia and ysoserial.exploit.RMIRegistryExploit).

### Disadvantages:
* Depends on a .jar file (wlthint3client.jar) that cannot be distributed by me (due to Oracle Licensing terms) and can only be downloaded with an Oracle username/password. Because of this, I can only distribute a "thin" release jar that still requires the user to obtain the required wlthint3client.jar file from Oracle.
* Due to issues with how the JVM loads classes during initialization, the usage of a full all-in-one executable WLT3Serial jar file (WLT3Serial-full-[VERSION].jar) is no longer supported. Therefore, WLT3Serial requires multiple files (outlined below) to run properly with full functionality.

# Building
Requires Oracle Java 7 or 8. Has not been tested with any other Java vendor (such as OpenJDK or IBM JRE), so I make no promises of support for these. Can likely be built with Java 9 or 10, but I make no promises of support for these.

WLT3Serial is built via the [Gradle](https://gradle.org/) build automation system. Gradle 4 should be used for building, although other versions have been partially tested (see Development section).

Third-Party Dependencies:

* [ysoserial](https://github.com/frohoff/ysoserial) - For generating object deserialization payloads; Version v0.0.5 or higher required (will be downloaded automatically by Gradle if not provided in advance by user.)
* wlthint3client - For handling T3/T3S connections natively; must be supplied by the user (due to Oracle Licensing terms): Can be downloaded (requires Oracle username/password) as part of wls1036_dev.zip file (located in /wlserver/server/lib/wlthint3client.jar) hosted on [this page](http://www.oracle.com/technetwork/middleware/weblogic/downloads/wls-main-097127.html) ("Zip distribution for Mac OSX, Windows, and Linux" under "Oracle WebLogic Server 10.3.6" section).

Procedure:

1. Clone the WLT3Serial repository. ```git clone https://github.com/Bort-Millipede/WLT3Serial.git```
2. Open terminal and navigate to cloned repository.
3. Execute the following command to create the preliminary build directory: ```gradle clean prepare```
4. Place downloaded wlthint3client.jar file in the build/libs/ directory.
5. (OPTIONAL) If using a preferred version of ysoserial (v0.0.5 or higher), place the ysoserial.jar file in the build/libs/ directory.
6. To build the WLT3Serial jar file (located at build/libs/WLT3Serial-[VERSION].jar), execute the following command: ```gradle build -x test```


# Usage
Requires Oracle Java 7 or 8. Has not been tested with any other Java vendor (such as OpenJDK or IBM JRE), so I make no promises of support for these. Can likely be used with Java 9 or 10, but I make no promises of support for these.

If using the Property (default), Bind or WLBind exploitation methods, WLT3Serial should be executed as such (note the value of the java '-cp' parameter):

* on *nix: ```java -cp /path/to/ysoserial.jar:/path/to/wlthint3client.jar:/path/to/WLT3Serial-[VERSION].jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```
* on Windows: ```java -cp \path\to\ysoserial.jar;\path\to\wlthint3client.jar;\path\to\WLT3Serial-[VERSION].jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```

If using the CustomClass exploitation method, WLT3Serial should be executed as such (note the value of the java '-cp' parameter):

* on *nix: ```java -cp /path/to/ysoserial.jar:/path/to/WLT3Serial-[VERSION].jar:/path/to/wlthint3client.jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```
* on Windows: ```java -cp \path\to\ysoserial.jar;\path\to\WLT3Serial-[VERSION].jar;\path\to\wlthint3client.jar bort.millipede.wlt3.WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD```

Below is the printout of the built-in help menu:

```shell
Usage: WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD

Options:
	--help				print usage (you're lookin at it)

	--verbose			Verbose output (full thrown exception output; Disabled by default)

	--method=EXPLOIT_METHOD		Exploit Method for delivering generated ysoserial payload
		Exploit Methods:
			Property	Send ysoserial payload as connection environment property value (Default; via javax.naming.Context.lookup(), variation of ysoserial.exploit.RMIRegistryExploit)
			Bind		Send ysoserial payload as object to bind to name (via javax.naming.Context.bind(), similar to ysoserial.exploit.RMIRegistryExploit)
			WLBind		Send ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)
			CustomClass	Send ysoserial payload during T3/T3S connection initialization (via custom weblogic.rjvm.ClassTableEntry class, similar to JavaUnserializeExploits weblogic.py)

	--t3s[=PROTOCOL]		Use T3S (transport-encrypted) connection (Disabled by default)
		Protocols:
			TLSv1.2
			TLSv1.1
			TLSv1 (Default)
			SSLv3
			SSLv2 (SSLv2Hello handshake only, then fallback to SSLv3 for communication: this is an Oracle Java limitation, not a WLT3Serial limitation)


Available Payload Types (WebLogic is usually vulnerable to "CommonsCollectionsX" and "JRMPClientX" types):
	(available payloads listed here)
```

## Exploit Method Notes
The Property, Bind, and WLBind methods are all very similar. This is to the point that if a target system cannot be exploited using one of these methods, then it likely cannot be exploited using any of them. The CustomClass method is completely different from the other methods.
### Advantages/Disadvantages of Property/Bind/WLBind Methods:
* Advantage: Because these methods perform attempted exploitation via available WebLogic classes/methods from the wlthint3client.jar file, T3/T3S communication is handled natively and meaningful output (Exceptions, stack traces, etc.) is generated to aid users in determining exploitation potential and success.
* Disadvantage: As of writing, Oracle has patched most (if not all) modes of exploitation using these methods.
### Advantage/Disadvantages of CustomClass Method:
* Advantage: Because this method attacks a different WebLogic classloader (which contains additional vulnerable libraries) than the above methods, newer successful modes of exploitation are available.
* Disadvantage: Because of the nature of how this method delivers payloads to target servers (by essentially crippling native T3/T3S communcation), meaningful output (Exceptions, stack traces, etc.) to aid users in determining exploitation potential and success cannot be generated

## T3S Connection Notes
it is recommended that the user does a scan of the target service with [sslscan](https://github.com/rbsec/sslscan) or the [nmap ssl-enum-ciphers script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html) to find out which protocols are supported. This way, the user can fine-tune the ```--t3s``` option when executing WLT3Serial.

# Development
In an attempt to improve upon the [JavaUnserializeExploits weblogic.py](https://github.com/breenmachine/JavaUnserializeExploits/blob/master/weblogic.py) and [loubia](https://github.com/metalnas/loubia) exploits, WLT3Serial was developed in Java using the following resources for connecting to WebLogic T3/T3S services:

* [https://docs.oracle.com/cd/E21764_01/web.1111/e13717/wlthint3client.htm](https://docs.oracle.com/cd/E21764_01/web.1111/e13717/wlthint3client.htm)
* [https://docs.oracle.com/cd/E13222_01/wls/docs92/jndi/jndi.html](https://docs.oracle.com/cd/E13222_01/wls/docs92/jndi/jndi.html)
* [https://docs.oracle.com/cd/E11035_01/wls100/javadocs/weblogic/rmi/Naming.html](https://docs.oracle.com/cd/E11035_01/wls100/javadocs/weblogic/rmi/Naming.html)
* [https://gist.github.com/fkrauthan/ac8624466a4dee4fd02f](https://gist.github.com/fkrauthan/ac8624466a4dee4fd02f)

Emphasis was placed on handling T3 connections natively in Java, as well as proper error handling to provide helpful command output for the user.

WLT3Serial was developed using the following software versions:

* Oracle Java 8 Update 191
* Oracle Java 7 Update 80 and Oracle Java 7 Update 17
* Gradle 4.10.2, 3.2 (partially tested), 2.10 (partially tested), 1.4 (partially tested)

Live testing during development was conducted against the following versions of WebLogic Server:

* 10.3.6
* 12.1.3
* 12.2.1.1 (only vulnerable to certain payload types and exploitation methods)
* 12.2.1.2 (only vulnerable to certain payload types and exploitation methods)
* 12.2.1.3 (partially vulnerable)

# Disclaimer
The developers provide the software for free without warranty, and assume no responsibility for any damage caused to systems by using the software. It is the responsibility of the user to abide by all local, state and federal laws while using the software.

# Copyright
(C) 2017, 2018 Jeffrey Cap (Bort_Millipede)

