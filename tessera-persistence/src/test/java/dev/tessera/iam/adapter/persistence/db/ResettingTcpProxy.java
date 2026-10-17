package dev.tessera.iam.adapter.persistence.db;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A TCP proxy that can turn the connections it already carries into dead ones, the way a NAT or
 * firewall that dropped an idle flow does, while new connections keep working.
 *
 * <p>{@link #doomExisting()} marks every open link. The next bytes the client sends on a marked
 * link are not forwarded: the proxy answers with a TCP reset ({@code SO_LINGER 0}) and closes the
 * upstream side, so the client sees {@code Connection reset by peer} exactly when it first reuses
 * the pooled connection. Links opened afterwards pass through untouched.
 *
 * <p>{@link #doomExistingOn(String)} marks them more selectively: the reset comes only with the
 * first client bytes that contain the given text, such as a table name, so a unit of work can be
 * cut off after its transaction began and its tenant was bound, when its own statements go out.
 *
 * <p>A small admin port takes one line per connection: {@code doom} or {@code doom-on <text>}
 * (answers the number of links marked) or {@code resets} (answers the number of resets sent so
 * far). The test drives it over TCP because the test resource and the test run in different class
 * loaders.
 */
final class ResettingTcpProxy implements AutoCloseable {

    private final String targetHost;
    private final int targetPort;
    private final ServerSocket listener;
    private final ServerSocket admin;
    private final Set<Link> links = ConcurrentHashMap.newKeySet();
    private final AtomicInteger resets = new AtomicInteger();
    private final ExecutorService threads = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "resetting-proxy");
        thread.setDaemon(true);
        return thread;
    });

    ResettingTcpProxy(String targetHost, int targetPort) throws IOException {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        InetAddress loopback = InetAddress.getLoopbackAddress();
        this.listener = new ServerSocket(0, 50, loopback);
        this.admin = new ServerSocket(0, 50, loopback);
        threads.execute(this::acceptLinks);
        threads.execute(this::acceptAdmin);
    }

    int port() {
        return listener.getLocalPort();
    }

    int adminPort() {
        return admin.getLocalPort();
    }

    int doomExisting() {
        links.forEach(link -> link.doomed = true);
        return links.size();
    }

    int doomExistingOn(String text) {
        byte[] marker = text.getBytes(StandardCharsets.UTF_8);
        links.forEach(link -> link.doomMarker = marker);
        return links.size();
    }

    int resets() {
        return resets.get();
    }

    private void acceptLinks() {
        while (!listener.isClosed()) {
            try {
                Socket client = listener.accept();
                Socket upstream = new Socket(targetHost, targetPort);
                Link link = new Link(client, upstream);
                links.add(link);
                threads.execute(() -> pumpClientToServer(link));
                threads.execute(() -> pumpServerToClient(link));
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void pumpClientToServer(Link link) {
        byte[] buffer = new byte[8192];
        try (InputStream in = link.client.getInputStream()) {
            OutputStream out = link.upstream.getOutputStream();
            int read;
            while ((read = in.read(buffer)) >= 0) {
                if (link.doomed || contains(buffer, read, link.doomMarker)) {
                    link.client.setSoLinger(true, 0);
                    resets.incrementAndGet();
                    break;
                }
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (IOException ignored) {
            // the other pump or close() ended the link
        } finally {
            link.close();
        }
    }

    private static boolean contains(byte[] buffer, int length, byte[] marker) {
        if (marker == null) {
            return false;
        }
        for (int i = 0; i + marker.length <= length; i++) {
            int j = 0;
            while (j < marker.length && buffer[i + j] == marker[j]) {
                j++;
            }
            if (j == marker.length) {
                return true;
            }
        }
        return false;
    }

    private void pumpServerToClient(Link link) {
        byte[] buffer = new byte[8192];
        try (InputStream in = link.upstream.getInputStream()) {
            OutputStream out = link.client.getOutputStream();
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (IOException ignored) {
            // the other pump or close() ended the link
        } finally {
            link.close();
        }
    }

    private void acceptAdmin() {
        while (!admin.isClosed()) {
            try (Socket socket = admin.accept();
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.US_ASCII)) {
                String command = in.readLine();
                if ("doom".equals(command)) {
                    out.println(doomExisting());
                } else if (command != null && command.startsWith("doom-on ")) {
                    out.println(doomExistingOn(command.substring("doom-on ".length())));
                } else if ("resets".equals(command)) {
                    out.println(resets());
                } else {
                    out.println("unknown");
                }
            } catch (IOException closed) {
                if (admin.isClosed()) {
                    return;
                }
            }
        }
    }

    /** Sends one admin command to a proxy listening on {@code adminPort} and returns its answer. */
    static String command(int adminPort, String command) {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), adminPort);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.US_ASCII);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))) {
            out.println(command);
            return in.readLine();
        } catch (IOException e) {
            throw new IllegalStateException("proxy admin command failed: " + command, e);
        }
    }

    @Override
    public void close() throws IOException {
        listener.close();
        admin.close();
        links.forEach(Link::close);
        threads.shutdownNow();
    }

    private final class Link {
        final Socket client;
        final Socket upstream;
        volatile boolean doomed;
        volatile byte[] doomMarker;

        Link(Socket client, Socket upstream) {
            this.client = client;
            this.upstream = upstream;
        }

        void close() {
            links.remove(this);
            closeQuietly(client);
            closeQuietly(upstream);
        }

        private static void closeQuietly(Socket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // already closed
            }
        }
    }
}
