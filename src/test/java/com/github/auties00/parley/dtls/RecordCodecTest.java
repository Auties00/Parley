package com.github.auties00.parley.dtls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Property and fuzz tests of the record and handshake codecs: the presentation-language reader and writer, the
/// record layer of both versions with sequence number reconstruction and replay rejection, and handshake
/// reassembly under random fragmentation, reordering and duplication.
@DisplayName("record and handshake codecs")
class RecordCodecTest {
    @Nested
    @DisplayName("TlsReader and TlsWriter")
    class Codec {
        @Test
        @DisplayName("round-trips integers and nested vectors")
        void roundTrip() throws Exception {
            var writer = new TlsWriter(4).u8(0xAB).u16(0xBEEF).u24(0x123456).u48(0x123456789ABCL).u64(-2);
            var outer = writer.open16();
            writer.vector8(new byte[]{1, 2}).vector24(new byte[300]);
            writer.close(outer);
            var reader = new TlsReader(writer.toByteArray());
            assertEquals(0xAB, reader.u8());
            assertEquals(0xBEEF, reader.u16());
            assertEquals(0x123456, reader.u24());
            assertEquals(0x123456789ABCL, reader.u48());
            assertEquals(-2, reader.u64());
            var nested = reader.sub16();
            assertArrayEquals(new byte[]{1, 2}, nested.vector8());
            assertEquals(300, nested.vector24().length);
            nested.expectEnd();
            reader.expectEnd();
        }

        @Test
        @DisplayName("refuses vectors larger than their length field")
        void oversized() {
            assertThrows(IllegalArgumentException.class, () -> new TlsWriter().vector8(new byte[256]));
            var writer = new TlsWriter();
            var mark = writer.open8();
            writer.bytes(new byte[256]);
            assertThrows(IllegalStateException.class, () -> writer.close(mark));
        }

        @Test
        @DisplayName("fails every read of random bytes with a decode_error, never another exception")
        void fuzz() {
            var random = new Random(11);
            for (var round = 0; round < 20_000; round++) {
                var bytes = new byte[random.nextInt(40)];
                random.nextBytes(bytes);
                var reader = new TlsReader(bytes);
                try {
                    while (true) {
                        switch (random.nextInt(6)) {
                            case 0 -> reader.u8();
                            case 1 -> reader.u24();
                            case 2 -> reader.vector8();
                            case 3 -> reader.sub16().vector16();
                            case 4 -> reader.vector24();
                            default -> reader.u64();
                        }
                    }
                } catch (DtlsException expected) {
                    assertEquals(DtlsAlert.DECODE_ERROR, expected.alert().orElseThrow());
                }
            }
        }

        @Test
        @DisplayName("parses random extension blocks without unexpected exceptions")
        void extensionFuzz() {
            var random = new Random(5);
            for (var round = 0; round < 20_000; round++) {
                var bytes = new byte[random.nextInt(30)];
                random.nextBytes(bytes);
                try {
                    Handshake.readExtensions(new TlsReader(bytes));
                    Handshake.readUseSrtp(bytes);
                    Handshake.readSignatureAlgorithms(bytes);
                    Handshake.readCertificate12(bytes);
                    Handshake.readCertificate13(bytes, new byte[0]);
                } catch (DtlsException expected) {
                    assertTrue(expected.alert().isPresent());
                }
            }
        }
    }

    @Nested
    @DisplayName("RecordLayer")
    class Records {
        private RecordLayer[] pair13() {
            var secret = new byte[32];
            var writer = new RecordLayer();
            var reader = new RecordLayer();
            writer.setVersion(DtlsVersion.DTLS_1_3);
            reader.setVersion(DtlsVersion.DTLS_1_3);
            for (var epoch = 2; epoch <= 5; epoch++) {
                secret[0] = (byte) epoch;
                writer.installWrite(epoch, Dtls13RecordCipher.fromSecret(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, secret));
                reader.installRead(epoch, Dtls13RecordCipher.fromSecret(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, secret));
            }
            return new RecordLayer[]{writer, reader};
        }

        private List<RecordLayer.Record> decode(RecordLayer layer, byte[] datagram) throws IOException {
            var records = new ArrayList<RecordLayer.Record>();
            layer.decode(datagram, records::add);
            return records;
        }

        @Test
        @DisplayName("round-trips DTLS 1.3 ciphertext across epochs and packs several records in a datagram")
        void dtls13() throws Exception {
            var layers = pair13();
            var first = layers[0].encode(RecordLayer.HANDSHAKE, 2, new byte[]{1, 2, 3}, 0xFEFD).bytes();
            var second = layers[0].encode(RecordLayer.APPLICATION_DATA, 3, new byte[40], 0xFEFD).bytes();
            assertEquals(0x2C | 2, first[0] & 0xFF);
            var datagram = TlsPrf.concat(first, second);
            var records = decode(layers[1], datagram);
            assertEquals(2, records.size());
            assertEquals(RecordLayer.HANDSHAKE, records.get(0).type());
            assertEquals(2, records.get(0).epoch());
            assertArrayEquals(new byte[]{1, 2, 3}, records.get(0).payload());
            assertEquals(3, records.get(1).epoch());
            assertTrue(decode(layers[1], datagram).isEmpty(), "replayed records are dropped");
            assertEquals(2, layers[1].dropped());
        }

        @Test
        @DisplayName("reconstructs 16-bit sequence numbers across wraps and with reordering")
        void longStream() throws Exception {
            var layers = pair13();
            var random = new Random(9);
            var pending = new ArrayList<byte[]>();
            var received = new HashSet<Long>();
            for (var sequence = 0; sequence < 70_000; sequence++) {
                pending.add(layers[0].encode(RecordLayer.APPLICATION_DATA, 3, new byte[]{(byte) sequence}, 0xFEFD).bytes());
                if (pending.size() == 8) {
                    Collections.shuffle(pending, random);
                    for (var datagram : pending) {
                        for (var record : decode(layers[1], datagram)) {
                            assertTrue(received.add(record.sequence()));
                        }
                    }
                    pending.clear();
                }
            }
            assertEquals(70_000, received.size());
        }

        @Test
        @DisplayName("round-trips DTLS 1.2 plaintext and protected records")
        void dtls12() throws Exception {
            var writer = new RecordLayer();
            var reader = new RecordLayer();
            writer.setVersion(DtlsVersion.DTLS_1_2);
            reader.setVersion(DtlsVersion.DTLS_1_2);
            writer.installWrite(1, new Dtls12RecordCipher(Aead.AES_256_GCM, new byte[32], new byte[4]));
            reader.installRead(1, new Dtls12RecordCipher(Aead.AES_256_GCM, new byte[32], new byte[4]));
            var plain = writer.encode(RecordLayer.HANDSHAKE, 0, new byte[]{9}, 0xFEFD).bytes();
            var sealed = writer.encode(RecordLayer.APPLICATION_DATA, 1, new byte[]{7, 7}, 0xFEFD).bytes();
            var records = decode(reader, TlsPrf.concat(plain, sealed));
            assertEquals(2, records.size());
            assertArrayEquals(new byte[]{9}, records.get(0).payload());
            assertArrayEquals(new byte[]{7, 7}, records.get(1).payload());
            sealed[sealed.length - 1] ^= 1;
            assertTrue(decode(reader, sealed).isEmpty());
            assertEquals(1, reader.authenticationFailures());
        }

        @Test
        @DisplayName("never throws on random datagrams")
        void fuzz() throws Exception {
            var layers = pair13();
            var random = new Random(17);
            for (var round = 0; round < 20_000; round++) {
                var bytes = new byte[random.nextInt(80)];
                random.nextBytes(bytes);
                if (bytes.length > 0 && random.nextBoolean()) {
                    bytes[0] = (byte) (0x20 | (bytes[0] & 0x1F));
                }
                decode(layers[1], bytes);
            }
            var valid = layers[0].encode(RecordLayer.APPLICATION_DATA, 4, new byte[]{1}, 0xFEFD).bytes();
            assertEquals(1, decode(layers[1], valid).size());
        }

        @ParameterizedTest(name = "{0}-bit")
        @ValueSource(ints = {8, 16})
        @DisplayName("picks the full sequence number closest to the expected one, ties excluded")
        void reconstruct(int bits) {
            var random = new Random(bits);
            var window = 1L << bits;
            for (var round = 0; round < 100_000; round++) {
                var expected = random.nextLong(1L << 40);
                var offset = random.nextLong(window - 1) - window / 2 + 1;
                var actual = Math.max(0, expected + offset);
                assertEquals(actual, RecordLayer.reconstruct(expected, actual & (window - 1), bits));
            }
        }
    }

    @Nested
    @DisplayName("ReplayWindow")
    class Replay {
        @Test
        @DisplayName("matches a model of every sequence number seen, within the window")
        void model() {
            var random = new Random(21);
            var window = new ReplayWindow();
            var seen = new HashSet<Long>();
            var highest = -1L;
            for (var round = 0; round < 200_000; round++) {
                var sequence = Math.max(0, highest + random.nextInt(140) - 100);
                var expected = !seen.contains(sequence) && (highest < 0 || highest - sequence < ReplayWindow.WIDTH);
                assertEquals(expected, window.isFresh(sequence), "sequence " + sequence + " highest " + highest);
                if (expected) {
                    window.mark(sequence);
                    seen.add(sequence);
                    highest = Math.max(highest, sequence);
                }
            }
        }
    }

    @Nested
    @DisplayName("HandshakeReassembler")
    class Reassembly {
        @Test
        @DisplayName("rebuilds messages from shuffled, overlapping and repeated fragments, in order")
        void shuffled() throws Exception {
            var random = new Random(31);
            for (var round = 0; round < 300; round++) {
                var reassembler = new HandshakeReassembler();
                reassembler.relax();
                var messages = new ArrayList<byte[]>();
                var fragments = new ArrayList<int[]>();
                for (var seq = 0; seq < 4; seq++) {
                    var body = new byte[random.nextInt(3000)];
                    random.nextBytes(body);
                    messages.add(body);
                    var offset = 0;
                    do {
                        var length = Math.min(body.length - offset, 1 + random.nextInt(700));
                        fragments.add(new int[]{seq, offset, length});
                        if (random.nextInt(4) == 0 && offset > 0) {
                            fragments.add(new int[]{seq, offset - 1, Math.min(length + 1, body.length - offset + 1)});
                        }
                        offset += length;
                    } while (offset < body.length);
                }
                var copies = new ArrayList<>(fragments);
                copies.addAll(fragments.subList(0, fragments.size() / 3));
                Collections.shuffle(copies, random);
                var released = new ArrayList<HandshakeMessage>();
                for (var fragment : copies) {
                    var body = messages.get(fragment[0]);
                    reassembler.offer(10 + fragment[0], body.length, fragment[0], fragment[1],
                            Arrays.copyOfRange(body, fragment[1], fragment[1] + fragment[2]), 0);
                    HandshakeReassembler.Received next;
                    while ((next = reassembler.poll().orElse(null)) != null) {
                        released.add(next.message());
                    }
                }
                assertEquals(4, released.size());
                for (var seq = 0; seq < 4; seq++) {
                    assertEquals(seq, released.get(seq).messageSeq());
                    assertEquals(10 + seq, released.get(seq).type());
                    assertArrayEquals(messages.get(seq), released.get(seq).body());
                }
                assertFalse(reassembler.hasPending());
            }
        }

        @Test
        @DisplayName("reports old messages, drops far-ahead ones and refuses oversized ones")
        void bounds() throws Exception {
            var reassembler = new HandshakeReassembler();
            assertEquals(HandshakeReassembler.Result.ACCEPTED, reassembler.offer(1, 1, 0, 0, new byte[1], 0));
            reassembler.poll().orElseThrow();
            assertEquals(HandshakeReassembler.Result.OLD, reassembler.offer(1, 1, 0, 0, new byte[1], 0));
            assertEquals(HandshakeReassembler.Result.DROPPED,
                    reassembler.offer(1, 1, 1 + HandshakeReassembler.MAX_LOOKAHEAD, 0, new byte[1], 0));
            assertThrows(DtlsException.class, () -> reassembler.offer(1, HandshakeReassembler.MAX_MESSAGE_LENGTH + 1, 1,
                    0, new byte[1], 0));
            assertThrows(DtlsException.class, () -> reassembler.offer(1, 4, 1, 3, new byte[2], 0));
        }

        @Test
        @DisplayName("lets fragments of a higher epoch replace those of a lower one")
        void epochs() throws Exception {
            var reassembler = new HandshakeReassembler();
            reassembler.offer(8, 4, 0, 0, new byte[]{9, 9}, 0);
            reassembler.offer(8, 4, 0, 0, new byte[]{1, 2}, 2);
            assertEquals(HandshakeReassembler.Result.DROPPED, reassembler.offer(8, 4, 0, 2, new byte[]{7, 7}, 0));
            reassembler.offer(8, 4, 0, 2, new byte[]{3, 4}, 2);
            var received = reassembler.poll().orElseThrow();
            assertEquals(2, received.epoch());
            assertArrayEquals(new byte[]{1, 2, 3, 4}, received.message().body());
        }
    }
}
