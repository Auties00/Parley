package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// Covers the length checks of the public extension parsers and the `Duration` form of the playout delay, with a
/// fuzz pass that allows no failure but [RtpFormatException].
@DisplayName("header extension bounds")
class ExtensionBoundsTest {
    @Test
    @DisplayName("refuses identifiers longer than 255 bytes with RtpFormatException (correctness-m6 fuzz input)")
    void identifiers() {
        var value = new byte[258];
        java.util.Arrays.fill(value, (byte) 'a');
        assertThrows(RtpFormatException.class, () -> Mid.parse(ByteBuffer.wrap(value)));
        assertThrows(RtpFormatException.class, () -> RtpStreamId.parse(ByteBuffer.wrap(value)));
        assertThrows(RtpFormatException.class, () -> RepairedRtpStreamId.parse(ByteBuffer.wrap(value)));
    }

    @Test
    @DisplayName("refuses an absolute capture time neither 8 nor 16 bytes long")
    void absCaptureTime() throws RtpFormatException {
        assertThrows(RtpFormatException.class, () -> AbsCaptureTime.parse(ByteBuffer.allocate(12)));
        assertEquals(8, AbsCaptureTime.parse(ByteBuffer.allocate(8)).encodedLength());
        assertEquals(16, AbsCaptureTime.parse(ByteBuffer.allocate(16)).encodedLength());
    }

    @Test
    @DisplayName("carries the playout delay limits as durations rounded down to 10 ms")
    void playoutDelay() throws RtpFormatException {
        var delay = new PlayoutDelay(Duration.ofMillis(105), Duration.ofSeconds(2));
        var buffer = ByteBuffer.allocate(3);
        delay.writeTo(buffer);
        var parsed = PlayoutDelay.parse(buffer.flip());
        assertEquals(Duration.ofMillis(100), parsed.minimum());
        assertEquals(Duration.ofSeconds(2), parsed.maximum());
        assertThrows(IllegalArgumentException.class, () -> new PlayoutDelay(Duration.ofSeconds(1), Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new PlayoutDelay(Duration.ZERO, PlayoutDelay.MAXIMUM.plusMillis(1)));
        assertThrows(IllegalArgumentException.class, () -> new PlayoutDelay(Duration.ofMillis(-1), Duration.ZERO));
    }

    @Test
    @DisplayName("parses random values with RtpFormatException as the only failure")
    void fuzz() {
        var random = new Random(0xE77);
        for (var i = 0; i < 20_000; i++) {
            var bytes = new byte[random.nextInt(300)];
            random.nextBytes(bytes);
            for (var parser : PARSERS) {
                try {
                    parser.parse(ByteBuffer.wrap(bytes));
                } catch (RtpFormatException expected) {
                    // malformed values fail this way only
                }
            }
        }
    }

    @FunctionalInterface
    private interface Parser {
        Object parse(ByteBuffer value) throws RtpFormatException;
    }

    private static final Parser[] PARSERS = {Mid::parse, RtpStreamId::parse, RepairedRtpStreamId::parse,
            AbsCaptureTime::parse, AbsSendTime::parse, AudioLevel::parse, ColorSpace::parse, CsrcAudioLevels::parse,
            PlayoutDelay::parse, TransmissionTimeOffset::parse, TransportSequenceNumber::parse,
            VideoContentType::parse, VideoOrientation::parse, VideoTiming::parse, DependencyDescriptor::parse};
}
