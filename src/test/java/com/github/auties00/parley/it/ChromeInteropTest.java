package com.github.auties00.parley.it;

import com.github.auties00.parley.datachannel.DataChannel;
import com.github.auties00.parley.datachannel.DataChannelMessage;
import com.github.auties00.parley.dtls.DtlsVersion;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.peer.JsepDescription;
import com.github.auties00.parley.peer.JsepType;
import com.github.auties00.parley.peer.Configuration;
import com.github.auties00.parley.peer.LocalTrack;
import com.github.auties00.parley.peer.PeerConnection;
import com.github.auties00.parley.peer.PeerConnectionEvent;
import com.github.auties00.parley.peer.PeerConnectionState;
import com.github.auties00.parley.peer.RemoteTrack;
import com.github.auties00.parley.peer.RtpSender;
import com.github.auties00.parley.peer.TransceiverDirection;
import com.github.auties00.parley.peer.TransceiverInit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/// A call between Parley and a headless Chrome: Parley offers audio, video and a data channel, the page answers and
/// sends Chrome's fake camera and microphone back, and both sides check what they received.
///
/// Parley sends Opus and VP8 frames from fixtures `generate-fixtures.html` recorded with WebCodecs, so Chrome's
/// decoders see a real bitstream. The test runs only when the system property `parley.chrome` or the environment
/// variable `PARLEY_CHROME` names a Chrome (Chrome for Testing in CI) executable; it is tagged `chrome`.
@Tag("chrome")
@DisplayName("Chrome interop")
@Timeout(value = 120, unit = TimeUnit.SECONDS)
class ChromeInteropTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    /// One encoded frame of a fixture.
    record FixtureFrame(boolean keyframe, byte[] data) {
    }

    /// Which side sends the offer.
    enum Offerer {
        PARLEY, CHROME
    }

    /// {@return every offerer with Parley restricted to DTLS 1.2, and with DTLS 1.3 forced on both sides}
    static Stream<Arguments> calls() {
        return Stream.of(Offerer.values()).flatMap(offerer -> Stream.of(Arguments.of(offerer, false),
                Arguments.of(offerer, true)));
    }

    @ParameterizedTest(name = "{0} offers, DTLS 1.3 forced: {1}")
    @MethodSource("calls")
    @DisplayName("connects to Chrome with Opus audio, VP8 video and a data channel in both directions")
    void call(Offerer offerer, boolean dtls13) throws Exception {
        var chrome = chromeExecutable();
        assumeTrue(chrome.isPresent(), "no Chrome: set parley.chrome or PARLEY_CHROME");
        var opus = fixture("opus.bin");
        var vp8 = fixture("vp8.bin");
        var page = resource("chrome-peer.html");
        var profile = Files.createTempDirectory("parley-chrome-");
        try (var server = SignalingServer.start(page);
             var pc = PeerConnection.create(Configuration.builder().tcpCandidates(false)
                     .dtlsVersions(Set.of(dtls13 ? DtlsVersion.DTLS_1_3 : DtlsVersion.DTLS_1_2))
                     .build())) {
            var events = new CopyOnWriteArrayList<PeerConnectionEvent>();
            var monitor = new Object();
            pc.addListener(event -> {
                events.add(event);
                synchronized (monitor) {
                    monitor.notifyAll();
                }
            });
            var audio = LocalTrack.audio("parley-audio");
            var video = LocalTrack.video("parley-video");
            Optional<DataChannel> created = Optional.empty();
            if (offerer == Offerer.PARLEY) {
                pc.addTransceiver(audio, TransceiverInit.of(TransceiverDirection.SENDRECV));
                pc.addTransceiver(video, TransceiverInit.of(TransceiverDirection.SENDRECV));
                preferFixtureCodecs(pc);
                created = Optional.of(pc.createDataChannel("chat"));
                pc.setLocalDescription(pc.createOffer());
                assertTrue(pc.awaitIceGatheringComplete(TIMEOUT), "gathering did not complete");
                server.publish("offer", pc.localDescription().orElseThrow().sdp());
            }

            var role = offerer == Offerer.PARLEY ? "answer" : "offer";
            var process = launch(chrome.get(), profile, server.url() + "?role=" + role, dtls13);
            try {
                if (offerer == Offerer.PARLEY) {
                    var answer = server.await("answer", TIMEOUT)
                            .orElseThrow(() -> new AssertionError("no answer from Chrome; page log " + server.logs()));
                    pc.setRemoteDescription(new JsepDescription(JsepType.ANSWER, answer));
                } else {
                    var offer = server.await("offer", TIMEOUT)
                            .orElseThrow(() -> new AssertionError("no offer from Chrome; page log " + server.logs()));
                    pc.setRemoteDescription(new JsepDescription(JsepType.OFFER, offer));
                    for (var transceiver : pc.getTransceivers()) {
                        transceiver.sender().replaceTrack(transceiver.kind() == MediaKind.AUDIO ? audio : video);
                        transceiver.setDirection(TransceiverDirection.SENDRECV);
                    }
                    preferFixtureCodecs(pc);
                    pc.setLocalDescription(pc.createAnswer());
                    assertTrue(pc.awaitIceGatheringComplete(TIMEOUT), "gathering did not complete");
                    server.publish("answer", pc.localDescription().orElseThrow().sdp());
                }
                awaitEvent(events, monitor, PeerConnectionEvent.ConnectionStateChanged.class,
                        event -> event.state() == PeerConnectionState.CONNECTED, server);
                assertTrue(pc.awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ZERO));
                var version = pc.getStats().all(com.github.auties00.parley.stats.TransportStats.class).getFirst()
                        .tlsVersion();
                assertEquals(Optional.of(dtls13 ? "FEFC" : "FEFD"), version, "the negotiated DTLS version");
                var channel = created.isPresent() ? created.get() : awaitEvent(events, monitor,
                        PeerConnectionEvent.DataChannel.class, event -> event.channel().label().equals("chat"),
                        server).channel();

                var running = new AtomicBoolean(true);
                var audioWriter = loop(running, opus, Duration.ofMillis(20), 960, MediaKind.AUDIO, audio);
                var videoWriter = loop(running, vp8, Duration.ofMillis(33), 3000, MediaKind.VIDEO, video);
                try {
                    assertDataChannel(channel);
                    var remoteTracks = new HashMap<MediaKind, RemoteTrack>();
                    for (var kind : MediaKind.values()) {
                        var track = awaitEvent(events, monitor, PeerConnectionEvent.Track.class,
                                event -> event.receiver().track().kind() == kind, server).receiver().track();
                        remoteTracks.put(kind, track);
                    }
                    assertAudioFromChrome(remoteTracks.get(MediaKind.AUDIO));
                    assertVideoFromChrome(remoteTracks.get(MediaKind.VIDEO));
                    var report = awaitReport(server, values -> number(values, "video.framesDecoded") >= 10
                            && number(values, "audio.packetsReceived") >= 25
                            && number(values, "audio.totalSamplesReceived") > 0
                            && values.getOrDefault("dcReceived", "").equals("ping"));
                    assertEquals("connected", report.get("connectionState"), "report: " + report);
                    assertTrue(number(report, "video.keyFramesDecoded") >= 1, "report: " + report);
                    assertEquals(320, number(report, "video.frameWidth"), "report: " + report);
                } finally {
                    running.set(false);
                    audioWriter.join();
                    videoWriter.join();
                }
            } finally {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                process.waitFor(10, TimeUnit.SECONDS);
            }
        } finally {
            deleteQuietly(profile);
        }
    }

    /// Limits every transceiver to the fixtures' codecs, Opus and VP8 (with its retransmission format).
    private static void preferFixtureCodecs(PeerConnection pc) {
        for (var transceiver : pc.getTransceivers()) {
            transceiver.setCodecPreferences(transceiver.kind() == MediaKind.AUDIO
                    ? capabilities(MediaKind.AUDIO, "audio/opus")
                    : capabilities(MediaKind.VIDEO, "video/VP8", "video/rtx"));
        }
    }

    /// Exchanges text both ways: Chrome greets as the channel opens and echoes what Parley sends.
    private static void assertDataChannel(DataChannel channel) throws Exception {
        assertTrue(channel.awaitOpen(TIMEOUT), "the data channel did not open: " + channel);
        assertEquals(new DataChannelMessage.Text("hello from chrome"), channel.receive(TIMEOUT)
                .orElseThrow(() -> new AssertionError("no greeting from Chrome on " + channel)));
        channel.send("ping");
        assertEquals(new DataChannelMessage.Text("echo:ping"), channel.receive(TIMEOUT).orElseThrow());
    }

    /// Reads Opus frames of Chrome's fake microphone: each starts with a TOC byte, so it is never empty.
    private static void assertAudioFromChrome(RemoteTrack track) throws InterruptedException {
        var frames = 0;
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        try (var stream = track.frames()) {
            while (frames < 25 && System.nanoTime() < deadline) {
                var frame = stream.next(Duration.ofMillis(500));
                if (frame.isPresent()) {
                    assertTrue(frame.get().data().remaining() > 0);
                    frames++;
                }
            }
        }
        assertTrue(frames >= 25, "Opus frames from Chrome: " + frames);
    }

    /// Reads VP8 frames of Chrome's fake camera until a key frame whose header carries the VP8 start code.
    private static void assertVideoFromChrome(RemoteTrack track) throws InterruptedException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        var frames = 0;
        try (var stream = track.frames()) {
        while (System.nanoTime() < deadline) {
            var frame = stream.next(Duration.ofMillis(500));
            if (frame.isEmpty()) {
                continue;
            }
            frames++;
            var data = frame.get().data();
            var start = data.position();
            var keyframe = data.remaining() > 10 && (data.get(start) & 1) == 0;
            if (frame.get().keyframe() && keyframe) {
                assertEquals(0x9d, data.get(start + 3) & 0xff);
                assertEquals(0x01, data.get(start + 4) & 0xff);
                assertEquals(0x2a, data.get(start + 5) & 0xff);
                return;
            }
        }
        }
        throw new AssertionError("no VP8 key frame from Chrome among " + frames + " frames");
    }

    /// {@return the capabilities of `kind` whose media type is one of `mimeTypes`, in that order}
    private static List<Codec> capabilities(MediaKind kind, String... mimeTypes) {
        var all = RtpSender.getCapabilities(kind).codecs();
        var result = new ArrayList<Codec>();
        for (var mimeType : mimeTypes) {
            all.stream().filter(codec -> codec.mimeType().equalsIgnoreCase(mimeType)).forEach(result::add);
        }
        return result;
    }

    /// Writes the fixture's frames in a loop at the fixture's frame rate until `running` is cleared.
    private static Thread loop(AtomicBoolean running, List<FixtureFrame> frames, Duration interval, long step,
                               MediaKind kind, LocalTrack track) {
        return Thread.ofVirtual().name("it-chrome-" + kind).start(() -> {
            var index = new AtomicInteger();
            var timestamp = 0L;
            while (running.get()) {
                var frame = frames.get(index.getAndIncrement() % frames.size());
                track.write(EncodedFrame.of(kind, ByteBuffer.wrap(frame.data()).asReadOnlyBuffer(), timestamp,
                        frame.keyframe()));
                timestamp += step;
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException exception) {
                    return;
                }
            }
        });
    }

    /// Waits for a report from the page that satisfies `condition`, returning the last report either way.
    private static Map<String, String> awaitReport(SignalingServer server, Predicate<Map<String, String>> condition)
            throws InterruptedException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        var last = Map.<String, String>of();
        while (System.nanoTime() < deadline) {
            var text = server.latest("report");
            if (text.isPresent()) {
                last = parseReport(text.get());
                if (condition.test(last)) {
                    return last;
                }
            }
            Thread.sleep(250);
        }
        throw new AssertionError("Chrome never reported the expected state; last report " + last + ", page log "
                + server.logs());
    }

    private static Map<String, String> parseReport(String text) {
        var result = new HashMap<String, String>();
        for (var line : text.split("\n")) {
            var equals = line.indexOf('=');
            if (equals > 0) {
                result.put(line.substring(0, equals), line.substring(equals + 1));
            }
        }
        return result;
    }

    private static long number(Map<String, String> report, String key) {
        try {
            return Long.parseLong(report.getOrDefault(key, "0"));
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    /// Waits until an event of `type` matching `predicate` was raised, returning it.
    private static <E extends PeerConnectionEvent> E awaitEvent(List<PeerConnectionEvent> events, Object monitor,
                                                                Class<E> type, Predicate<? super E> predicate,
                                                                SignalingServer server) throws InterruptedException {
        var deadline = System.nanoTime() + TIMEOUT.toNanos();
        synchronized (monitor) {
            while (true) {
                for (var event : events) {
                    if (type.isInstance(event) && predicate.test(type.cast(event))) {
                        return type.cast(event);
                    }
                }
                var left = deadline - System.nanoTime();
                if (left <= 0) {
                    throw new AssertionError("no " + type.getSimpleName() + " event; events " + events
                            + ", page log " + server.logs() + ", last report " + server.latest("report"));
                }
                monitor.wait(Math.max(1, left / 1_000_000));
            }
        }
    }

    /// Starts Chrome headless on `url`: fake media devices granted without a prompt, host candidates with plain
    /// addresses (no mDNS names), autoplay allowed, and no sandbox, which CI containers and some Windows
    /// directories do not permit.
    private static Process launch(Path chrome, Path profile, String url, boolean dtls13) throws IOException {
        var command = new ArrayList<>(List.of(chrome.toString(),
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--user-data-dir=" + profile,
                "--use-fake-device-for-media-stream",
                "--use-fake-ui-for-media-stream",
                "--autoplay-policy=no-user-gesture-required",
                "--disable-features=WebRtcHideLocalIpsWithMdns"));
        if (dtls13) {
            command.add("--force-fieldtrials=WebRTC-ForceDtls13/Enabled/");
        }
        command.add(url);
        return new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(profile.resolve("chrome.log").toFile())
                .start();
    }

    /// {@return the Chrome executable the test runs against, if one is configured and exists}
    private static Optional<Path> chromeExecutable() {
        var configured = Optional.ofNullable(System.getProperty("parley.chrome"))
                .or(() -> Optional.ofNullable(System.getenv("PARLEY_CHROME")))
                .filter(value -> !value.isBlank());
        return configured.map(Path::of).filter(Files::isRegularFile);
    }

    /// {@return the frames of a fixture: per frame a flag byte (1 for a key frame), a big-endian length and the bytes}
    private static List<FixtureFrame> fixture(String name) throws IOException {
        var bytes = ByteBuffer.wrap(resourceBytes(name));
        var frames = new ArrayList<FixtureFrame>();
        while (bytes.hasRemaining()) {
            var keyframe = bytes.get() == 1;
            var data = new byte[bytes.getInt()];
            bytes.get(data);
            frames.add(new FixtureFrame(keyframe, data));
        }
        return List.copyOf(frames);
    }

    private static String resource(String name) throws IOException {
        return new String(resourceBytes(name), StandardCharsets.UTF_8);
    }

    private static byte[] resourceBytes(String name) throws IOException {
        try (var input = ChromeInteropTest.class.getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing test resource " + name);
            }
            return input.readAllBytes();
        }
    }

    private static void deleteQuietly(Path directory) {
        // Chrome may hold files for a moment after it exits; a leftover temporary profile is harmless
        try (var paths = Files.walk(directory)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException exception) {
                    // ignored, see above
                }
            });
        } catch (IOException | UncheckedIOException exception) {
            // ignored, see above
        }
    }
}
