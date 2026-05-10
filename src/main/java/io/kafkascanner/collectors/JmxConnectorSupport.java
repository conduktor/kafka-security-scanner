package io.kafkascanner.collectors;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

final class JmxConnectorSupport {

    private JmxConnectorSupport() {
    }

    @SuppressWarnings("BanJNDI")
    static JMXConnector connect(String url, Duration timeout) throws IOException {
        return JMXConnectorFactory.connect(new JMXServiceURL(url), environment(timeout));
    }

    static Map<String, Object> environment(Duration timeout) {
        var timeoutMillis = timeoutMillis(timeout);
        var env = new HashMap<String, Object>();
        env.put("com.sun.jndi.rmi.factory.socket", new TimeoutRmiClientSocketFactory(timeoutMillis));
        env.put("jmx.remote.x.request.waiting.timeout", Long.valueOf(timeoutMillis));
        env.put("jmx.remote.x.notification.fetch.timeout", Long.valueOf(timeoutMillis));
        return env;
    }

    static int timeoutMillis(Duration timeout) {
        var millis = timeout.toMillis();
        if (millis <= 0) {
            return 1;
        }
        return millis > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) millis;
    }

    private record TimeoutRmiClientSocketFactory(int timeoutMillis)
        implements RMIClientSocketFactory, Serializable {

        @Serial
        private static final long serialVersionUID = 1L;

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            var socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            return socket;
        }
    }
}
