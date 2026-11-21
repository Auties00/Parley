package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static com.github.auties00.parley.payload.TestPackets.bytes;
import static com.github.auties00.parley.payload.TestPackets.packet;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the audio payload formats: Opus (RFC 7587 parameters, RFC 6716 TOC durations), the RFC 3551 sample and
/// frame codecs, comfort noise (RFC 3389), the talkspurt marker and the audio level extension.
@DisplayName("audio payload formats")
class AudioPayloadTest {
    @Nested
    @DisplayName("PayloadFormat.of")
    class Selection {
        @Test
        @DisplayName("picks the format of each codec")
        void picks() {
            assertInstanceOf(OpusFormat.class, PayloadFormat.of(Codec.opus()));
            assertInstanceOf(AudioFormat.class, PayloadFormat.of(Codec.pcmu()));
            assertInstanceOf(AudioFormat.class, PayloadFormat.of(Codec.of("audio/iLBC", 8000)));
            assertInstanceOf(ComfortNoiseFormat.class, PayloadFormat.of(Codec.of("audio/CN", 8000)));
            assertInstanceOf(TelephoneEventFormat.class, PayloadFormat.of(Codec.telephoneEvent(48000)));
            assertInstanceOf(Vp8Format.class, PayloadFormat.of(Codec.vp8()));
            assertInstanceOf(Vp9Format.class, PayloadFormat.of(Codec.vp9()));
            assertInstanceOf(H264Format.class, PayloadFormat.of(Codec.h264()));
            assertInstanceOf(H265Format.class, PayloadFormat.of(Codec.h265()));
            assertInstanceOf(Av1Format.class, PayloadFormat.of(Codec.av1()));
            assertInstanceOf(GenericFormat.class, PayloadFormat.of(Codec.of("video/x-custom", 90000)));
        }

        @ParameterizedTest
        @ValueSource(strings = {"video/rtx", "video/red", "video/ulpfec", "video/flexfec-03", "audio/red"})
        @DisplayName("rejects repair formats")
        void rejectsRepair(String type) {
            assertThrows(IllegalArgumentException.class, () -> PayloadFormat.of(Codec.of(type, 90000)));
        }

        @Test
        @DisplayName("rejects Opus outside opus/48000/2")
        void rejectsOpus() {
            assertThrows(IllegalArgumentException.class, () -> PayloadFormat.of(Codec.of("audio/opus", 16000, 2)));
        }
    }

    @Nested
    @DisplayName("Opus")
    class Opus {
        @ParameterizedTest(name = "TOC {0} -> {1} samples")
        @CsvSource({
                "0x00, 480", "0x08, 960", "0x10, 1920", "0x18, 2880",
                "0x60, 480", "0x68, 960", "0x78, 960",
                "0x80, 120", "0x88, 240", "0x90, 480", "0x98, 960", "0xF8, 960",
                "0xF9, 1920", "0xFA, 1920", "0x1A, 5760"
        })
        @DisplayName("reads the duration from the TOC byte")
        void durations(String toc, int samples) {
            var payload = bytes(Integer.decode(toc), 0, 0);
            assertEquals(OptionalInt.of(samples), OpusFormat.defaults().timestampDuration(payload));
        }

        @Test
        @DisplayName("reads code 3 frame counts and rejects packets over 120 ms")
        void code3() {
            var format = OpusFormat.defaults();
            assertEquals(OptionalInt.of(3 * 960), format.timestampDuration(bytes(0xFB, 0x03, 0)));
            assertTrue(format.timestampDuration(bytes(0xFB, 0x07)).isEmpty());
            assertTrue(format.timestampDuration(bytes(0xFB)).isEmpty());
            assertTrue(format.timestampDuration(bytes(0xFB, 0x00)).isEmpty());
            assertTrue(format.timestampDuration(ByteBuffer.allocate(0)).isEmpty());
        }

        @Test
        @DisplayName("treats one- and two-byte packets as DTX")
        void dtx() {
            assertTrue(OpusFormat.isDtx(bytes(0xF8)));
            assertTrue(OpusFormat.isDtx(bytes(0xF8, 0x01)));
            assertFalse(OpusFormat.isDtx(bytes(0xF8, 1, 2)));
            assertFalse(OpusFormat.isDtx(ByteBuffer.allocate(0)));
        }

        @Test
        @DisplayName("parses the RFC 7587 example parameters and ignores invalid values")
        void parameters() {
            var parsed = OpusParameters.parse(Codec.parseFormatParameters(
                    "maxplaybackrate=16000; sprop-maxcapturerate=16000; maxaveragebitrate=20000; stereo=1; "
                            + "useinbandfec=1; usedtx=0"));
            assertEquals(OptionalInt.of(16000), parsed.maxPlaybackRate());
            assertEquals(OptionalInt.of(16000), parsed.spropMaxCaptureRate());
            assertEquals(OptionalInt.of(20000), parsed.maxAverageBitrate());
            assertTrue(parsed.stereo());
            assertTrue(parsed.useInbandFec());
            assertFalse(parsed.useDtx());
            var invalid = OpusParameters.parse(Map.of("maxplaybackrate", "100", "ptime", "x", "stereo", "yes"));
            assertEquals(OpusParameters.defaults(), invalid);
            assertEquals(Map.of("maxplaybackrate", "16000", "sprop-maxcapturerate", "16000",
                    "maxaveragebitrate", "20000", "stereo", "1", "useinbandfec", "1"), parsed.toFormatParameters());
            assertEquals(parsed, OpusParameters.parse(parsed.toFormatParameters()));
            assertThrows(IllegalArgumentException.class, () -> new OpusParameters(OptionalInt.of(1), OptionalInt.empty(),
                    OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty(), false, false,
                    false, false, false));
            var codec = Codec.opus().withFormatParameters(Map.of("useinbandfec", "1"));
            assertTrue(new OpusFormat(codec).parameters().useInbandFec());
        }

        @Test
        @DisplayName("marks the first packet of each talkspurt")
        void talkspurtMarker() {
            var packetizer = OpusFormat.defaults().packetizer();
            var frame = bytes(0x78, 1, 2, 3);
            assertTrue(packetizer.packetize(audio(frame, 0)).getFirst().marker());
            assertFalse(packetizer.packetize(audio(frame, 960)).getFirst().marker());
            assertFalse(packetizer.packetize(audio(frame, 1920)).getFirst().marker());
            assertTrue(packetizer.packetize(audio(frame, 9600)).getFirst().marker());
        }

        @Test
        @DisplayName("round-trips a frame with its level and contributing sources")
        void roundTrip() throws PayloadFormatException {
            var format = OpusFormat.defaults();
            var frame = new EncodedFrame(MediaKind.AUDIO, bytes(0x78, 9, 9), 4800, true, Optional.empty(),
                    AudioFrameMetadata.ofLevel(42, true));
            var payload = format.packetizer().packetize(frame).getFirst();
            var level = payload.extensions().get(HeaderExtensionUris.AUDIO_LEVEL);
            assertEquals(0x80 | 42, level.get(0) & 0xFF);
            var packet = packet(111, payload.marker(), 7, 4800, 1, payload.payload(),
                    Map.of(3, new byte[]{(byte) (0x80 | 42)}), List.of(11L, 12L));
            var depacketizer = format.depacketizer(DepacketizerConfig.none().withAudioLevelExtensionId(3));
            assertTrue(depacketizer.inspect(packet).frameStart());
            var assembled = depacketizer.assemble(List.of(packet));
            assertArrayEquals(new byte[]{0x78, 9, 9}, assembled.toByteArray());
            assertEquals(4800, assembled.rtpTimestamp());
            assertTrue(assembled.keyframe());
            var metadata = (AudioFrameMetadata) assembled.metadata();
            assertEquals(OptionalInt.of(42), metadata.audioLevelDbov());
            assertTrue(metadata.voiceActivity());
            assertEquals(List.of(11L, 12L), metadata.contributingSources());
        }

        @Test
        @DisplayName("rejects empty payloads, multi-packet frames and oversized frames")
        void rejects() {
            var format = OpusFormat.defaults();
            assertFalse(format.depacketizer().inspect(packet(111, false, 1, 0, ByteBuffer.allocate(0))).valid());
            var one = packet(111, false, 1, 0, bytes(0x78));
            var two = packet(111, false, 2, 0, bytes(0x78));
            assertThrows(PayloadFormatException.class, () -> format.depacketizer().assemble(List.of(one, two)));
            assertThrows(IllegalArgumentException.class,
                    () -> format.packetizer().packetize(audio(ByteBuffer.allocate(2000), 0)));
            assertThrows(IllegalArgumentException.class, () -> format.packetizer().packetize(
                    EncodedFrame.of(MediaKind.VIDEO, bytes(1), 0, true)));
        }
    }

    @Nested
    @DisplayName("RFC 3551 codecs")
    class Simple {
        @ParameterizedTest(name = "{0}/{1}/{2} with {3} bytes -> {4}")
        @CsvSource({
                "PCMU, 8000, 1, 160, 160",
                "PCMA, 8000, 2, 320, 160",
                "G722, 8000, 1, 160, 160",
                "L16, 16000, 2, 640, 160",
                "GSM, 8000, 1, 66, 320",
                "G729, 8000, 1, 22, 160",
                "iLBC, 8000, 1, 38, 160",
                "iLBC, 8000, 1, 50, 240",
                "PCMU, 8000, 2, 161, -1",
                "iLBC, 8000, 1, 39, -1",
                "AMR, 8000, 1, 32, -1"
        })
        @DisplayName("knows the duration of sample and frame based codecs")
        void durations(String name, int clock, int channels, int length, int expected) {
            var format = PayloadFormat.of(Codec.of("audio/" + name, clock, channels));
            var duration = format.timestampDuration(ByteBuffer.allocate(length));
            assertEquals(expected < 0 ? OptionalInt.empty() : OptionalInt.of(expected), duration);
        }

        @Test
        @DisplayName("decodes G.711 buffers like the arrays")
        void g711() {
            var pcm = new short[]{0, 100, -100, 32767, -32768};
            var alaw = G711.encodeALaw(pcm, pcm.length);
            var mulaw = G711.encodeMuLaw(pcm, pcm.length);
            assertArrayEquals(G711.decodeALaw(alaw), G711.decodeALaw(ByteBuffer.wrap(alaw)));
            assertArrayEquals(G711.decodeMuLaw(mulaw), G711.decodeMuLaw(ByteBuffer.wrap(mulaw)));
            assertEquals((byte) 0xD5, G711.encodeALaw(new short[]{0}, 1)[0]);
            assertEquals((byte) 0xFF, G711.encodeMuLaw(new short[]{0}, 1)[0]);
        }

        @Test
        @DisplayName("marks talkspurts of PCMU by the sample count")
        void pcmuMarker() {
            var packetizer = PayloadFormat.of(Codec.pcmu()).packetizer();
            assertTrue(packetizer.packetize(audio(ByteBuffer.allocate(160), 0)).getFirst().marker());
            assertFalse(packetizer.packetize(audio(ByteBuffer.allocate(160), 160)).getFirst().marker());
            assertTrue(packetizer.packetize(audio(ByteBuffer.allocate(160), 800)).getFirst().marker());
        }
    }

    @Nested
    @DisplayName("comfort noise")
    class Noise {
        @Test
        @DisplayName("round-trips a level and reflection coefficients")
        void roundTrip() throws PayloadFormatException {
            var noise = new ComfortNoise(64, List.of(127, 3, 255));
            var buffer = noise.toBuffer();
            assertArrayEquals(new byte[]{64, 127, 3, (byte) 255}, TestPackets.array(buffer));
            assertEquals(noise, ComfortNoise.parse(buffer));
            assertEquals(new ComfortNoise(127, List.of()), ComfortNoise.parse(bytes(127)));
        }

        @Test
        @DisplayName("rejects empty payloads, the reserved bit and out-of-range values")
        void rejects() {
            assertThrows(PayloadFormatException.class, () -> ComfortNoise.parse(ByteBuffer.allocate(0)));
            assertThrows(PayloadFormatException.class, () -> ComfortNoise.parse(bytes(0x80)));
            assertThrows(IllegalArgumentException.class, () -> new ComfortNoise(128, List.of()));
            var format = PayloadFormat.of(Codec.of("audio/CN", 8000));
            assertFalse(format.depacketizer().inspect(packet(13, false, 1, 0, bytes(0x80))).valid());
            assertTrue(format.depacketizer().inspect(packet(13, false, 1, 0, bytes(0x40))).valid());
            assertTrue(format.timestampDuration(bytes(0x40)).isEmpty());
        }
    }

    /// {@return an audio frame}
    static EncodedFrame audio(ByteBuffer data, long timestamp) {
        return EncodedFrame.of(MediaKind.AUDIO, data, timestamp, true);
    }
}
