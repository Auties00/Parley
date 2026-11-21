package com.github.auties00.parley.it;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/// A minimal HTTP/1.1 server on 127.0.0.1 that serves one page and relays signaling between a test and that page.
///
/// `GET /` returns the page (whatever its query). `GET /<name>` blocks until the test has published `<name>` (the offer) and returns it.
/// `POST /<name>` stores the body under `<name>` (the answer, the reports), replacing the previous one, and
/// `POST /log` appends a line to [#logs()]. Each connection carries one request and is closed after the response.
final class SignalingServer implements AutoCloseable {
    private final ServerSocket socket;
    private final byte[] page;
    private final Map<String, String> values = new ConcurrentHashMap<>();
    private final List<String> logs = new CopyOnWriteArrayList<>();
    private final Object monitor = new Object();
    private final Thread acceptor;

    private SignalingServer(ServerSocket socket, byte[] page) {
        this.socket = socket;
        this.page = page;
        this.acceptor = Thread.ofVirtual().name("it-http-accept").start(this::acceptLoop);
    }

    /// {@return a server serving `page` on an ephemeral loopback port}
    static SignalingServer start(String page) throws IOException {
        var socket = new ServerSocket();
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        return new SignalingServer(socket, page.getBytes(StandardCharsets.UTF_8));
    }

    /// {@return the URL of the page}
    String url() {
        return "http://127.0.0.1:" + socket.getLocalPort() + "/";
    }

    /// Publishes `value` under `name`, waking a page blocked on `GET /<name>`.
    void publish(String name, String value) {
        synchronized (monitor) {
            values.put(name, value);
            monitor.notifyAll();
        }
    }

    /// Waits up to `timeout` for a value posted or published under `name`.
    Optional<String> await(String name, Duration timeout) throws InterruptedException {
        var deadline = System.nanoTime() + timeout.toNanos();
        synchronized (monitor) {
            while (true) {
                var value = values.get(name);
                if (value != null) {
                    return Optional.of(value);
                }
                var left = deadline - System.nanoTime();
                if (left <= 0) {
                    return Optional.empty();
                }
                monitor.wait(Math.max(1, left / 1_000_000));
            }
        }
    }

    /// {@return the latest value posted under `name`, if any}
    Optional<String> latest(String name) {
        return Optional.ofNullable(values.get(name));
    }

    /// {@return the lines the page logged}
    List<String> logs() {
        return List.copyOf(logs);
    }

    private void acceptLoop() {
        while (!socket.isClosed()) {
            try {
                var client = socket.accept();
                Thread.ofVirtual().name("it-http").start(() -> serve(client));
            } catch (IOException exception) {
                return;
            }
        }
    }

    private void serve(Socket client) {
        try (client) {
            var input = client.getInputStream();
            var requestLine = readLine(input);
            if (requestLine == null) {
                return;
            }
            var parts = requestLine.split(" ");
            var method = parts[0];
            var path = parts.length > 1 ? parts[1] : "/";
            var length = 0;
            String header;
            while ((header = readLine(input)) != null && !header.isEmpty()) {
                var colon = header.indexOf(':');
                if (colon > 0 && header.substring(0, colon).trim().toLowerCase(Locale.ROOT).equals("content-length")) {
                    length = Integer.parseInt(header.substring(colon + 1).trim());
                }
            }
            var body = input.readNBytes(length);
            var output = client.getOutputStream();
            var query = path.indexOf('?');
            var name = path.substring(1, query < 0 ? path.length() : query);
            switch (method) {
                case "GET" -> {
                    if (name.isEmpty()) {
                        respond(output, 200, "text/html; charset=utf-8", page);
                    } else if (name.equals("favicon.ico")) {
                        respond(output, 404, "text/plain", new byte[0]);
                    } else {
                        var value = await(name, Duration.ofSeconds(60));
                        respond(output, value.isPresent() ? 200 : 504, "text/plain; charset=utf-8",
                                value.orElse("").getBytes(StandardCharsets.UTF_8));
                    }
                }
                case "POST" -> {
                    var text = new String(body, StandardCharsets.UTF_8);
                    if (name.equals("log")) {
                        logs.add(text);
                    } else {
                        publish(name, text);
                    }
                    respond(output, 204, "text/plain", new byte[0]);
                }
                default -> respond(output, 405, "text/plain", new byte[0]);
            }
        } catch (IOException | InterruptedException exception) {
            // The page reloads or the test ends; one lost request is retried by the page's next report
        }
    }

    private static String readLine(InputStream input) throws IOException {
        var buffer = new ByteArrayOutputStream();
        int read;
        while ((read = input.read()) != -1) {
            if (read == '\n') {
                var line = buffer.toString(StandardCharsets.ISO_8859_1);
                return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
            }
            buffer.write(read);
        }
        return buffer.size() == 0 ? null : buffer.toString(StandardCharsets.ISO_8859_1);
    }

    private static void respond(OutputStream output, int status, String type, byte[] body) throws IOException {
        var head = "HTTP/1.1 " + status + " X\r\nContent-Type: " + type + "\r\nContent-Length: " + body.length
                + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
        output.write(head.getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
        output.flush();
    }

    @Override
    public void close() throws IOException {
        socket.close();
        acceptor.interrupt();
    }
}
