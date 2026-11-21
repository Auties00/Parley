package com.github.auties00.parley.rtp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the RTP packet view and writer: fixed header, CSRCs, padding and both RFC 8285 extension forms, with the
/// RFC 8285 figures as vectors and a random round-trip and fuzz pass.
@DisplayName("RTP packet view and writer")
class RtpPacketTest {
    private static final HexFormat HEX = HexFormat.of();

    static byte[] bytes(ByteBuffer buffer) {
        var out = new byte[buffer.remaining()];
        buffer.duplicate().get(out);
        return out;
    }

    @Nested
    @DisplayName("fixed header")
    class FixedHeader {
        @Test
        @DisplayName("writes and reads every fixed field at its extreme values")
        void extremes() throws RtpFormatException {
            var packet = RtpPacketWriter.into(ByteBuffer.allocate(64))
                    .payloadType(127).marker(true).sequence(65535).timestamp(0xFFFFFFFFL).ssrc(0xFFFFFFFFL)
                    .payload(ByteBuffer.wrap(new byte[]{1, 2, 3})).finish();
            var view = RtpPacket.parse(packet);
            assertEquals(127, view.payloadType());
            assertTrue(view.marker());
            assertEquals(65535, view.sequence());
            assertEquals(0xFFFFFFFFL, view.timestamp());
            assertEquals(0xFFFFFFFFL, view.ssrc());
            assertArrayEquals(new byte[]{1, 2, 3}, bytes(view.payload()));
            assertEquals(15, view.length());
            assertFalse(view.hasExtension());
            assertEquals(0, view.extensionProfile());
            assertTrue(view.payload().isReadOnly());
        }

        @Test
        @DisplayName("matches a hand-encoded packet byte for byte")
        void vector() throws RtpFormatException {
            var expected = HEX.parseHex("80e01234" + "00000960" + "deadbeef" + "aabb");
            var packet = RtpPacketWriter.into(ByteBuffer.allocate(14))
                    .payloadType(96).marker(true).sequence(0x1234).timestamp(2400).ssrc(0xDEADBEEFL)
                    .payload(ByteBuffer.wrap(new byte[]{(byte) 0xAA, (byte) 0xBB})).finish();
            assertArrayEquals(expected, bytes(packet));
        }

        @Test
        @DisplayName("keeps CSRCs and strips padding")
        void csrcsAndPadding() throws RtpFormatException {
            var buffer = ByteBuffer.allocate(100);
            var packet = RtpPacketWriter.into(buffer).payloadType(0).sequence(1).timestamp(2).ssrc(3)
                    .csrcs(List.of(10L, 0xFFFFFFFFL)).padding(7)
                    .payload(ByteBuffer.wrap(new byte[]{9, 9})).finish();
            var view = RtpPacket.parse(packet);
            assertEquals(List.of(10L, 0xFFFFFFFFL), view.csrcs());
            assertEquals(7, view.paddingLength());
            assertEquals(2, view.payloadLength());
            assertEquals(12 + 8 + 2 + 7, view.length());
            assertEquals(view.length(), buffer.position());
        }

        @Test
        @DisplayName("leaves the tailroom after the limit for in-place protection")
        void tailroom() {
            var buffer = ByteBuffer.allocate(40);
            buffer.position(4);
            var packet = RtpPacketWriter.into(buffer).payload(ByteBuffer.wrap(new byte[4])).finish();
            assertEquals(4, packet.position());
            assertEquals(20, packet.limit());
            assertEquals(40, packet.capacity());
        }

        @Test
        @DisplayName("refuses a destination too small for the packet")
        void overflow() {
            var writer = RtpPacketWriter.into(ByteBuffer.allocate(12)).payload(ByteBuffer.wrap(new byte[1]));
            assertThrows(BufferOverflowException.class, writer::finish);
        }

        @Test
        @DisplayName("copies into an independent buffer")
        void copy() throws RtpFormatException {
            var buffer = ByteBuffer.allocate(64);
            buffer.position(10);
            var packet = RtpPacketWriter.into(buffer).ssrc(5).extension(3, ByteBuffer.wrap(new byte[]{1, 2}))
                    .payload(ByteBuffer.wrap(new byte[]{7})).finish();
            var view = RtpPacket.parse(packet);
            var copy = view.copy();
            buffer.put(10 + 12 + 4 + 1, (byte) 99);
            assertEquals(99, view.extension(3).orElseThrow().get(0));
            assertEquals(1, copy.extension(3).orElseThrow().get(0));
            assertEquals(5, copy.ssrc());
            assertEquals(7, copy.payload().get(0));
            assertEquals(17, copy.extensionOffset(3).orElseThrow());
        }
    }

    @Nested
    @DisplayName("header extensions")
    class Extensions {
        @Test
        @DisplayName("reads the one-byte example of RFC 8285 section 4.2")
        void oneByteFigure() throws RtpFormatException {
            var packet = HEX.parseHex("90000001" + "00000000" + "00000001"
                    + "bede0003" + "10aa21bbbb000033" + "cccccccc");
            var view = RtpPacket.parse(ByteBuffer.wrap(packet));
            assertEquals(RtpPacket.ONE_BYTE_PROFILE, view.extensionProfile());
            assertEquals(List.of(1, 2, 3), view.extensionIds());
            assertArrayEquals(HEX.parseHex("aa"), bytes(view.extension(1).orElseThrow()));
            assertArrayEquals(HEX.parseHex("bbbb"), bytes(view.extension(2).orElseThrow()));
            assertArrayEquals(HEX.parseHex("cccccccc"), bytes(view.extension(3).orElseThrow()));
            assertEquals(0, view.payloadLength());
        }

        @Test
        @DisplayName("reads the two-byte example of RFC 8285 section 4.3")
        void twoByteFigure() throws RtpFormatException {
            var packet = HEX.parseHex("90000001" + "00000000" + "00000001"
                    + "10000003" + "01000201" + "aa000304" + "dddddddd" + "ff");
            var view = RtpPacket.parse(ByteBuffer.wrap(packet));
            assertTrue(view.hasTwoByteExtensions());
            assertEquals(List.of(1, 2, 3), view.extensionIds());
            assertEquals(0, view.extension(1).orElseThrow().remaining());
            assertArrayEquals(HEX.parseHex("aa"), bytes(view.extension(2).orElseThrow()));
            assertArrayEquals(HEX.parseHex("dddddddd"), bytes(view.extension(3).orElseThrow()));
            assertArrayEquals(HEX.parseHex("ff"), bytes(view.payload()));
        }

        @Test
        @DisplayName("stops at the one-byte id 15 and keeps other profiles opaque")
        void reservedAndOpaque() throws RtpFormatException {
            var stop = HEX.parseHex("90000001000000000000000" + "1" + "bede0001" + "10aaf000");
            assertEquals(List.of(1), RtpPacket.parse(ByteBuffer.wrap(stop)).extensionIds());
            var opaque = HEX.parseHex("9000000100000000" + "00000001" + "12340001" + "01020304");
            var view = RtpPacket.parse(ByteBuffer.wrap(opaque));
            assertEquals(0x1234, view.extensionProfile());
            assertTrue(view.extensionIds().isEmpty());
            assertArrayEquals(HEX.parseHex("01020304"), bytes(view.extensionData().orElseThrow()));
        }

        @Test
        @DisplayName("switches to the two-byte form for large ids, long values and empty values")
        void formSelection() throws RtpFormatException {
            var oneByte = RtpPacket.parse(RtpPacketWriter.into(ByteBuffer.allocate(64))
                    .extension(14, ByteBuffer.wrap(new byte[16])).finish());
            assertEquals(RtpPacket.ONE_BYTE_PROFILE, oneByte.extensionProfile());
            for (var writer : List.of(
                    RtpPacketWriter.into(ByteBuffer.allocate(64)).extension(15, ByteBuffer.wrap(new byte[1])),
                    RtpPacketWriter.into(ByteBuffer.allocate(64)).extension(1, ByteBuffer.wrap(new byte[17])),
                    RtpPacketWriter.into(ByteBuffer.allocate(64)).extension(1, ByteBuffer.allocate(0)),
                    RtpPacketWriter.into(ByteBuffer.allocate(64)).extension(1, ByteBuffer.wrap(new byte[1]))
                            .twoByteExtensions(true))) {
                var view = RtpPacket.parse(writer.finish());
                assertTrue(view.hasTwoByteExtensions());
            }
        }

        @Test
        @DisplayName("exposes the absolute offset of an element for in-place stamping")
        void offset() throws RtpFormatException {
            var buffer = ByteBuffer.allocate(64);
            buffer.position(8);
            var packet = RtpPacketWriter.into(buffer).extension(5, ByteBuffer.allocate(2)).finish();
            var offset = RtpPacket.parse(packet).extensionOffset(5).orElseThrow();
            assertEquals(8 + 12 + 4 + 1, offset);
            buffer.putShort(offset, (short) 0x1234);
            assertEquals(0x1234, RtpPacket.parse(packet).extension(5).orElseThrow().getShort(0));
        }

        @Test
        @DisplayName("rejects duplicate ids and out-of-range ids when writing")
        void writerChecks() {
            var writer = RtpPacketWriter.into(ByteBuffer.allocate(64)).extension(1, ByteBuffer.allocate(1));
            assertThrows(IllegalArgumentException.class, () -> writer.extension(1, ByteBuffer.allocate(1)));
            assertThrows(IllegalArgumentException.class, () -> writer.extension(0, ByteBuffer.allocate(1)));
            assertThrows(IllegalArgumentException.class, () -> writer.extension(256, ByteBuffer.allocate(1)));
        }
    }

    @Nested
    @DisplayName("malformed input")
    class Malformed {
        @Test
        @DisplayName("rejects short packets, wrong versions and overruns")
        void rejects() {
            for (var hex : List.of("8000", "400000010000000000000001", "8f00000100000000000000010000",
                    "9000000100000000000000010000", "90000001000000000000000100000002aabbccdd",
                    "a0000001000000000000000100", "a000000100000000000000010a",
                    "9000000100000000000000011000000101ff0000", "900000010000000000000001bede000133020000")) {
                assertThrows(RtpFormatException.class, () -> RtpPacket.parse(ByteBuffer.wrap(HEX.parseHex(hex))),
                        hex);
            }
        }

        @RepeatedTest(20)
        @DisplayName("throws only RtpFormatException on random bytes")
        void fuzz() {
            var random = new Random();
            for (var i = 0; i < 2_000; i++) {
                var data = new byte[random.nextInt(64)];
                random.nextBytes(data);
                if (data.length > 0 && random.nextBoolean()) {
                    data[0] = (byte) (0x80 | data[0] & 0x3F);
                }
                try {
                    var view = RtpPacket.parse(ByteBuffer.wrap(data));
                    view.payload();
                    view.csrcs();
                    for (var id : view.extensionIds()) {
                        view.extension(id).orElseThrow();
                    }
                    assertTrue(view.headerLength() + view.payloadLength() + view.paddingLength() == view.length());
                } catch (RtpFormatException expected) {
                    // malformed input is reported, never anything else
                }
            }
        }
    }

    @RepeatedTest(50)
    @DisplayName("round-trips random packets through the writer and the view")
    void roundTrip() throws RtpFormatException {
        var random = new Random();
        var csrcs = new ArrayList<Long>();
        for (var i = random.nextInt(16); i > 0; i--) {
            csrcs.add(random.nextLong() & 0xFFFFFFFFL);
        }
        var payload = new byte[random.nextInt(200)];
        random.nextBytes(payload);
        var writer = RtpPacketWriter.into(ByteBuffer.allocate(1500))
                .payloadType(random.nextInt(128)).marker(random.nextBoolean()).sequence(random.nextInt(65536))
                .timestamp(random.nextLong() & 0xFFFFFFFFL).ssrc(random.nextLong() & 0xFFFFFFFFL).csrcs(csrcs)
                .padding(random.nextInt(4) == 0 ? 1 + random.nextInt(255) : 0)
                .twoByteExtensions(random.nextBoolean()).payload(ByteBuffer.wrap(payload));
        var values = new ArrayList<byte[]>();
        var ids = new ArrayList<Integer>();
        for (var i = random.nextInt(5); i > 0; i--) {
            var id = 1 + random.nextInt(14);
            if (ids.contains(id)) {
                continue;
            }
            var value = new byte[1 + random.nextInt(16)];
            random.nextBytes(value);
            ids.add(id);
            values.add(value);
            writer.extension(id, ByteBuffer.wrap(value));
        }
        var packet = writer.finish();
        var view = RtpPacket.parse(packet);
        assertEquals(csrcs, view.csrcs());
        assertArrayEquals(payload, bytes(view.payload()));
        assertEquals(ids, view.extensionIds());
        for (var i = 0; i < ids.size(); i++) {
            assertArrayEquals(values.get(i), bytes(view.extension(ids.get(i)).orElseThrow()));
        }
        assertEquals(view.header(), view.copy().header());
    }
}
