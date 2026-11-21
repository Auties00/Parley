package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static com.github.auties00.parley.payload.TestPackets.array;
import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers RFC 4733 telephone events: the event block codec, the format's event list and marker, the W3C
/// `insertDTMF` timing of [DtmfToneSequence], and the receiver-side [TelephoneEventDetector].
@DisplayName("telephone events")
class TelephoneEventTest {
    @Nested
    @DisplayName("event block")
    class Block {
        @Test
        @DisplayName("encodes the RFC 4733 layout: event, E bit, volume, 16-bit duration")
        void encodes() {
            var event = new TelephoneEvent(1, true, 10, 1000);
            assertArrayEquals(new byte[]{1, (byte) 0x8A, 0x03, (byte) 0xE8}, array(event.toBuffer()));
            assertArrayEquals(new byte[]{11, 0x3F, (byte) 0xFF, (byte) 0xFF},
                    array(new TelephoneEvent(11, false, 63, 65535).toBuffer()));
        }

        @Test
        @DisplayName("parses one block, ignoring the reserved bit and trailing bytes, and several packed blocks")
        void parses() throws PayloadFormatException {
            assertEquals(new TelephoneEvent(1, true, 10, 1000), TelephoneEvent.parse(bytes(1, 0xCA, 3, 0xE8, 9)));
            assertEquals(List.of(new TelephoneEvent(1, true, 10, 400), new TelephoneEvent(2, false, 10, 160)),
                    TelephoneEvent.parseAll(bytes(1, 0x8A, 1, 0x90, 2, 0x0A, 0, 0xA0)));
            assertThrows(PayloadFormatException.class, () -> TelephoneEvent.parse(bytes(1, 2, 3)));
            assertThrows(PayloadFormatException.class, () -> TelephoneEvent.parseAll(bytes(1, 2, 3, 4, 5)));
            assertThrows(PayloadFormatException.class, () -> TelephoneEvent.parseAll(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("maps DTMF characters to events and back")
        void symbols() {
            var expected = "0123456789*#ABCD";
            for (var i = 0; i < expected.length(); i++) {
                assertEquals(OptionalInt.of(i), TelephoneEvent.eventOf(expected.charAt(i)));
                assertEquals(Optional.of(expected.charAt(i)), new TelephoneEvent(i, false, 0, 0).symbol());
            }
            assertEquals(OptionalInt.of(12), TelephoneEvent.eventOf('a'));
            assertTrue(TelephoneEvent.eventOf('E').isEmpty());
            assertTrue(new TelephoneEvent(TelephoneEvent.FLASH, false, 0, 0).symbol().isEmpty());
        }

        @Test
        @DisplayName("rejects out-of-range fields")
        void rejects() {
            assertThrows(IllegalArgumentException.class, () -> new TelephoneEvent(256, false, 0, 0));
            assertThrows(IllegalArgumentException.class, () -> new TelephoneEvent(0, false, 64, 0));
            assertThrows(IllegalArgumentException.class, () -> new TelephoneEvent(0, false, 0, 65536));
        }
    }

    @Nested
    @DisplayName("format")
    class Format {
        @Test
        @DisplayName("reads the event list, defaulting to 0-15")
        void events() {
            var format = new TelephoneEventFormat(Codec.telephoneEvent(8000).withFormatParameters(Map.of("", "0-16,32")));
            var events = format.events();
            assertTrue(events.get(16));
            assertTrue(events.get(32));
            assertFalse(events.get(17));
            var defaults = new TelephoneEventFormat(Codec.of("audio/telephone-event", 8000)).events();
            assertEquals(16, defaults.cardinality());
            var malformed = new TelephoneEventFormat(Codec.of("audio/telephone-event", 8000)
                    .withFormatParameters(Map.of("", "x-3"))).events();
            assertEquals(16, malformed.cardinality());
        }

        @Test
        @DisplayName("sets the marker on each new event and round-trips the payload")
        void packetizes() throws PayloadFormatException {
            var format = new TelephoneEventFormat(Codec.telephoneEvent(8000));
            var packetizer = format.packetizer();
            var block = new TelephoneEvent(5, false, 10, 400).toBuffer();
            assertTrue(packetizer.packetize(EncodedFrame.of(MediaKind.AUDIO, block, 100, true)).getFirst().marker());
            assertFalse(packetizer.packetize(EncodedFrame.of(MediaKind.AUDIO, block, 100, true)).getFirst().marker());
            assertTrue(packetizer.packetize(EncodedFrame.of(MediaKind.AUDIO, block, 900, true)).getFirst().marker());
            assertThrows(IllegalArgumentException.class,
                    () -> packetizer.packetize(EncodedFrame.of(MediaKind.AUDIO, bytes(1, 2), 0, true)));
            var frame = format.depacketizer().assemble(List.of(packet(101, true, 1, 100, block)));
            assertEquals(new TelephoneEvent(5, false, 10, 400), TelephoneEvent.parse(frame.data()));
            assertFalse(format.depacketizer().inspect(packet(101, true, 1, 100, bytes(1, 2))).valid());
        }
    }

    @Nested
    @DisplayName("DtmfToneSequence")
    class Sequence {
        @Test
        @DisplayName("normalises tones and clamps times as insertDTMF does")
        void normalises() {
            var tones = new DtmfToneSequence("1a#,*", Duration.ofMillis(10), Duration.ofMillis(5));
            assertEquals("1A#,*", tones.tones());
            assertEquals(Duration.ofMillis(40), tones.duration());
            assertEquals(Duration.ofMillis(30), tones.interToneGap());
            var long_ = new DtmfToneSequence("1", Duration.ofSeconds(9), Duration.ofSeconds(9));
            assertEquals(Duration.ofMillis(6000), long_.duration());
            assertEquals(Duration.ofMillis(6000), long_.interToneGap());
            assertEquals(DtmfToneSequence.DEFAULT_DURATION, DtmfToneSequence.of("1").duration());
        }

        @ParameterizedTest
        @ValueSource(strings = {"1E", "12 3", "#!", "p"})
        @DisplayName("rejects characters insertDTMF does not accept")
        void rejects(String tones) {
            assertThrows(IllegalArgumentException.class, () -> DtmfToneSequence.of(tones));
        }

        @Test
        @DisplayName("starts each tone after the previous tone and gap, a comma after two seconds")
        void startTimes() {
            var tones = DtmfToneSequence.of("1,2");
            assertEquals(List.of(Duration.ZERO, Duration.ofMillis(170), Duration.ofMillis(2170)), tones.startTimes());
            assertEquals(Duration.ofMillis(2340), tones.totalDuration());
        }

        @Test
        @DisplayName("sends a 100 ms tone at 8 kHz every 50 ms, then its end three times")
        void packets() {
            var packets = DtmfToneSequence.of("1").packets(8000);
            assertEquals(5, packets.size());
            assertEquals(new DtmfToneSequence.Packet(Duration.ZERO, '1', 0, true, new TelephoneEvent(1, false, 10, 400)),
                    packets.get(0));
            assertEquals(new DtmfToneSequence.Packet(Duration.ofMillis(50), '1', 0, false,
                    new TelephoneEvent(1, false, 10, 800)), packets.get(1));
            for (var i = 2; i < 5; i++) {
                assertEquals(new DtmfToneSequence.Packet(Duration.ofMillis(100), '1', 0, false,
                        new TelephoneEvent(1, true, 10, 800)), packets.get(i));
            }
        }

        @Test
        @DisplayName("timestamps the second tone at its start time")
        void secondTone() {
            var packets = DtmfToneSequence.of("12").packets(48000, Duration.ofMillis(20), 5);
            var second = packets.stream().filter(packet -> packet.tone() == '2').toList();
            assertTrue(second.getFirst().marker());
            assertEquals(Duration.ofMillis(170), second.getFirst().sendTime());
            assertEquals(170 * 48, second.getFirst().timestampOffset());
            assertEquals(960, second.getFirst().event().duration());
            assertEquals(4800, second.getLast().event().duration());
            assertTrue(second.getLast().event().end());
            var frame = second.getFirst().toFrame(0xFFFFFFF0L);
            assertEquals((0xFFFFFFF0L + 170 * 48) & 0xFFFFFFFFL, frame.rtpTimestamp());
        }

        @Test
        @DisplayName("splits a tone longer than the duration field into segments")
        void segments() {
            var packets = new DtmfToneSequence("5", Duration.ofMillis(3000), Duration.ofMillis(70))
                    .packets(48000, Duration.ofMillis(50), 10);
            var offsets = packets.stream().map(DtmfToneSequence.Packet::timestampOffset).distinct().toList();
            assertEquals(List.of(0L, 65535L, 131070L), offsets);
            for (var packet : packets) {
                assertTrue(packet.event().duration() <= 65535);
                assertTrue(packet.event().duration() > 0);
            }
            assertEquals(1, packets.stream().filter(DtmfToneSequence.Packet::marker).count());
            var end = packets.getLast();
            assertTrue(end.event().end());
            assertEquals(144000 - 131070, end.event().duration());
        }

        @Test
        @DisplayName("produces nothing for a pause-only sequence and validates its arguments")
        void edges() {
            assertTrue(DtmfToneSequence.of(",,").packets(8000).isEmpty());
            assertThrows(IllegalArgumentException.class, () -> DtmfToneSequence.of("1").packets(0));
            assertThrows(IllegalArgumentException.class,
                    () -> DtmfToneSequence.of("1").packets(8000, Duration.ZERO, 10));
            assertThrows(IllegalArgumentException.class,
                    () -> DtmfToneSequence.of("1").packets(8000, Duration.ofMillis(50), 64));
        }
    }

    @Nested
    @DisplayName("TelephoneEventDetector")
    class Detector {
        @Test
        @DisplayName("reports an event once, at its first end packet")
        void once() throws PayloadFormatException {
            var detector = new TelephoneEventDetector();
            assertTrue(detector.accept(frame(100, 1, false, 400)).isEmpty());
            assertTrue(detector.accept(frame(100, 1, false, 800)).isEmpty());
            var ended = detector.accept(frame(100, 1, true, 800));
            assertEquals(List.of(new TelephoneEventDetector.DetectedEvent(1, Optional.of('1'), 100, 800, 10, true)),
                    ended);
            assertTrue(detector.accept(frame(100, 1, true, 800)).isEmpty());
            assertTrue(detector.accept(frame(100, 1, true, 800)).isEmpty());
        }

        @Test
        @DisplayName("closes an event whose end was lost when the next one starts, and ignores older ones")
        void lostEnd() throws PayloadFormatException {
            var detector = new TelephoneEventDetector();
            detector.accept(frame(100, 1, false, 400));
            var result = detector.accept(frame(2000, 2, false, 400));
            assertEquals(1, result.size());
            assertFalse(result.getFirst().ended());
            assertEquals(400, result.getFirst().duration());
            assertTrue(detector.accept(frame(100, 1, true, 800)).isEmpty());
            assertEquals('2', detector.accept(frame(2000, 2, true, 800)).getFirst().symbol().orElseThrow());
        }

        /// {@return a telephone-event frame}
        private static EncodedFrame frame(long timestamp, int event, boolean end, int duration) {
            return EncodedFrame.of(MediaKind.AUDIO, new TelephoneEvent(event, end, 10, duration).toBuffer(), timestamp,
                    true);
        }
    }
}
