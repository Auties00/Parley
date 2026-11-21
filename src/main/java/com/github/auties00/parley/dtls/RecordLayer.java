package com.github.auties00.parley.dtls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/// Encodes and decodes the DTLS records of one association, both record formats, with the keys of every epoch.
///
/// Epoch 0 records are `DTLSPlaintext` in either version. DTLS 1.2 protects epoch 1 records under the same 13-byte
/// header. DTLS 1.3 protects epochs 2 and above as `DTLSCiphertext` with the unified header, always written here with
/// a 16-bit sequence number and a length, and with the sequence number encrypted:
///
/// ```text
/// DTLSPlaintext : type(1) || version(2) || epoch(2) || sequence(6) || length(2) || fragment
/// DTLSCiphertext: 0b001 C S L EE (1) || sequence(1 or 2) || [length(2)] || encrypted(DTLSInnerPlaintext)
/// ```
///
/// Decoding authenticates each record, rejects replays with a [ReplayWindow] per epoch, and silently drops anything
/// malformed, from an unknown epoch or failing authentication, counting it; one bad record never ends the
/// association.
///
/// Instances are not thread-safe; the connection uses one under its lock.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html#section-4.1 RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html#section-4 RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
final class RecordLayer {
    /// The `change_cipher_spec` content type, DTLS 1.2 only.
    static final int CHANGE_CIPHER_SPEC = 20;

    /// The `alert` content type.
    static final int ALERT = 21;

    /// The `handshake` content type.
    static final int HANDSHAKE = 22;

    /// The `application_data` content type.
    static final int APPLICATION_DATA = 23;

    /// The `ack` content type, DTLS 1.3 only.
    static final int ACK = 26;

    /// The length of a `DTLSPlaintext` header.
    static final int PLAINTEXT_HEADER_LENGTH = 13;

    /// The length of the unified header this layer writes: flags, 16-bit sequence number and length.
    static final int UNIFIED_HEADER_LENGTH = 5;

    /// The largest plaintext a record carries.
    static final int MAX_PLAINTEXT = 1 << 14;

    /// One decoded and authenticated record.
    ///
    /// @param type     the content type, the inner one for DTLS 1.3 ciphertext
    /// @param epoch    the epoch
    /// @param sequence the sequence number
    /// @param payload  the plaintext payload
    record Record(int type, long epoch, long sequence, byte[] payload) {
    }

    /// The keys and sequence numbers of the write epochs, by epoch.
    private final Map<Long, WriteState> writeStates = new HashMap<>();

    /// The keys and replay windows of the read epochs, by epoch.
    private final Map<Long, ReadState> readStates = new HashMap<>();

    /// The negotiated version, `null` until the `ServerHello`; it decides the format of protected records.
    private DtlsVersion version;

    /// The records dropped since creation.
    private long dropped;

    /// The records that failed authentication since creation.
    private long authenticationFailures;

    /// Creates a record layer with only the plaintext epoch 0 in both directions.
    RecordLayer() {
        writeStates.put(0L, new WriteState(null, null));
        readStates.put(0L, new ReadState(null, null));
    }

    /// Sets the negotiated version.
    ///
    /// @param version the version
    void setVersion(DtlsVersion version) {
        this.version = version;
    }

    /// Installs the protection of a DTLS 1.2 write epoch.
    ///
    /// @param epoch  the epoch
    /// @param cipher the protection
    void installWrite(long epoch, Dtls12RecordCipher cipher) {
        writeStates.put(epoch, new WriteState(cipher, null));
    }

    /// Installs the protection of a DTLS 1.3 write epoch.
    ///
    /// @param epoch  the epoch
    /// @param cipher the protection
    void installWrite(long epoch, Dtls13RecordCipher cipher) {
        writeStates.put(epoch, new WriteState(null, cipher));
    }

    /// Installs the protection of a DTLS 1.2 read epoch.
    ///
    /// @param epoch  the epoch
    /// @param cipher the protection
    void installRead(long epoch, Dtls12RecordCipher cipher) {
        readStates.put(epoch, new ReadState(cipher, null));
    }

    /// Installs the protection of a DTLS 1.3 read epoch.
    ///
    /// @param epoch  the epoch
    /// @param cipher the protection
    void installRead(long epoch, Dtls13RecordCipher cipher) {
        readStates.put(epoch, new ReadState(null, cipher));
    }

    /// Forgets read epochs below `epoch`, except epoch 0, once records of a newer one authenticated.
    ///
    /// @param epoch the oldest epoch to keep
    void dropReadEpochsBelow(long epoch) {
        readStates.keySet().removeIf(key -> key != 0 && key < epoch);
    }

    /// {@return whether a read epoch is installed}
    ///
    /// @param epoch the epoch
    boolean hasReadEpoch(long epoch) {
        return readStates.containsKey(epoch);
    }

    /// {@return whether a write epoch is installed}
    ///
    /// @param epoch the epoch
    boolean hasWriteEpoch(long epoch) {
        return writeStates.containsKey(epoch);
    }

    /// {@return the bytes a record of an epoch adds around its payload}
    ///
    /// @param epoch the epoch
    int overhead(long epoch) {
        var state = writeStates.get(epoch);
        if (state == null || (state.cipher12 == null && state.cipher13 == null)) {
            return PLAINTEXT_HEADER_LENGTH;
        }
        if (state.cipher12 != null) {
            return PLAINTEXT_HEADER_LENGTH + state.cipher12.overhead();
        }
        return UNIFIED_HEADER_LENGTH + 1 + Aead.TAG_LENGTH;
    }

    /// Encodes one record in an epoch, advancing its sequence number.
    ///
    /// @param type          the content type
    /// @param epoch         the write epoch, which must be installed
    /// @param payload       the plaintext payload
    /// @param recordVersion the version of a `DTLSPlaintext` header; ignored for DTLS 1.3 ciphertext
    /// @return the encoded record and its record number
    /// @throws DtlsException if protection fails
    EncodedRecord encode(int type, long epoch, byte[] payload, int recordVersion) throws DtlsException {
        var state = writeStates.get(epoch);
        if (state == null) {
            throw new DtlsException(DtlsAlert.INTERNAL_ERROR, "write epoch " + epoch + " is not installed");
        }
        var sequence = state.nextSequence++;
        if (state.cipher13 != null) {
            return new EncodedRecord(encode13(state.cipher13, type, epoch, sequence, payload), epoch, sequence);
        }
        var fragment = state.cipher12 == null
                ? payload
                : state.cipher12.seal(epoch << 48 | sequence, type, recordVersion, payload);
        var record = new TlsWriter(PLAINTEXT_HEADER_LENGTH + fragment.length)
                .u8(type).u16(recordVersion).u16((int) epoch).u48(sequence).u16(fragment.length).bytes(fragment)
                .toByteArray();
        return new EncodedRecord(record, epoch, sequence);
    }

    /// An encoded record with its record number.
    ///
    /// @param bytes    the record bytes
    /// @param epoch    the epoch
    /// @param sequence the sequence number
    record EncodedRecord(byte[] bytes, long epoch, long sequence) {
    }

    /// Receives the records of a datagram one at a time.
    @FunctionalInterface
    interface RecordHandler {
        /// Handles one authenticated record.
        ///
        /// @param record the record
        /// @throws IOException if handling fails, which stops decoding the datagram
        void handle(Record record) throws IOException;
    }

    /// Decodes and authenticates the records of one datagram, handing each to `handler` before decoding the next, so
    /// keys a record installs apply to the records after it in the same datagram.
    ///
    /// @param datagram the datagram
    /// @param handler  the handler of each authenticated record
    /// @throws IOException if the handler fails
    void decode(byte[] datagram, RecordHandler handler) throws IOException {
        var offset = 0;
        var decoded = new ArrayList<Record>(1);
        while (offset < datagram.length) {
            var first = datagram[offset] & 0xFF;
            int consumed;
            if ((first & 0xE0) == 0x20) {
                consumed = decode13(datagram, offset, decoded);
            } else {
                consumed = decodePlaintextHeader(datagram, offset, decoded);
            }
            if (consumed <= 0) {
                dropped++;
                break;
            }
            offset += consumed;
            for (var record : decoded) {
                handler.handle(record);
            }
            decoded.clear();
        }
    }

    /// {@return the records dropped since creation}
    long dropped() {
        return dropped;
    }

    /// {@return the records that failed authentication since creation}
    long authenticationFailures() {
        return authenticationFailures;
    }

    /// Encodes one DTLS 1.3 ciphertext record.
    private byte[] encode13(Dtls13RecordCipher cipher, int type, long epoch, long sequence, byte[] payload)
            throws DtlsException {
        var inner = new byte[payload.length + 1];
        System.arraycopy(payload, 0, inner, 0, payload.length);
        inner[payload.length] = (byte) type;
        var length = inner.length + Aead.TAG_LENGTH;
        var header = new byte[]{(byte) (0x2C | (epoch & 3)), (byte) (sequence >>> 8), (byte) sequence,
                (byte) (length >>> 8), (byte) length};
        var ciphertext = cipher.seal(sequence, header, inner);
        var mask = cipher.mask(ciphertext, 0);
        header[1] ^= mask[0];
        header[2] ^= mask[1];
        var record = new byte[header.length + ciphertext.length];
        System.arraycopy(header, 0, record, 0, header.length);
        System.arraycopy(ciphertext, 0, record, header.length, ciphertext.length);
        return record;
    }

    /// Decodes one record with a 13-byte header at `offset`.
    ///
    /// @return the bytes consumed, or `0` when the rest of the datagram must be dropped
    private int decodePlaintextHeader(byte[] datagram, int offset, List<Record> records) {
        if (datagram.length - offset < PLAINTEXT_HEADER_LENGTH) {
            return 0;
        }
        var type = datagram[offset] & 0xFF;
        if (type < CHANGE_CIPHER_SPEC || type > ACK || type == 24 || type == 25) {
            return 0;
        }
        var recordVersion = (datagram[offset + 1] & 0xFF) << 8 | (datagram[offset + 2] & 0xFF);
        var epoch = (long) ((datagram[offset + 3] & 0xFF) << 8 | (datagram[offset + 4] & 0xFF));
        var sequence = 0L;
        for (var index = 5; index < 11; index++) {
            sequence = sequence << 8 | (datagram[offset + index] & 0xFF);
        }
        var length = (datagram[offset + 11] & 0xFF) << 8 | (datagram[offset + 12] & 0xFF);
        if (length > datagram.length - offset - PLAINTEXT_HEADER_LENGTH) {
            return 0;
        }
        var total = PLAINTEXT_HEADER_LENGTH + length;
        if ((recordVersion & 0xFF00) != 0xFE00) {
            dropped++;
            return total;
        }
        var state = readStates.get(epoch);
        if (state == null || state.cipher13 != null || (epoch != 0 && state.cipher12 == null)) {
            dropped++;
            return total;
        }
        if (!state.window.isFresh(sequence)) {
            dropped++;
            return total;
        }
        byte[] payload;
        if (state.cipher12 == null) {
            payload = java.util.Arrays.copyOfRange(datagram, offset + PLAINTEXT_HEADER_LENGTH, offset + total);
        } else {
            try {
                payload = state.cipher12.open(epoch << 48 | sequence, type, recordVersion, datagram,
                        offset + PLAINTEXT_HEADER_LENGTH, length);
            } catch (DtlsException exception) {
                dropped++;
                authenticationFailures++;
                return total;
            }
        }
        if (payload.length > MAX_PLAINTEXT) {
            dropped++;
            return total;
        }
        state.window.mark(sequence);
        records.add(new Record(type, epoch, sequence, payload));
        return total;
    }

    /// Decodes one DTLS 1.3 ciphertext record at `offset`.
    ///
    /// @return the bytes consumed, or `0` when the rest of the datagram must be dropped
    private int decode13(byte[] datagram, int offset, List<Record> records) {
        var flags = datagram[offset] & 0xFF;
        if ((flags & 0x10) != 0) {
            return 0;
        }
        var sequenceLength = (flags & 0x08) != 0 ? 2 : 1;
        var lengthPresent = (flags & 0x04) != 0;
        var headerLength = 1 + sequenceLength + (lengthPresent ? 2 : 0);
        if (datagram.length - offset < headerLength) {
            return 0;
        }
        int length;
        if (lengthPresent) {
            var at = offset + 1 + sequenceLength;
            length = (datagram[at] & 0xFF) << 8 | (datagram[at + 1] & 0xFF);
            if (length > datagram.length - offset - headerLength) {
                return 0;
            }
        } else {
            length = datagram.length - offset - headerLength;
        }
        var total = headerLength + length;
        if (version != DtlsVersion.DTLS_1_3 || length < Dtls13RecordCipher.MASK_SAMPLE) {
            dropped++;
            return total;
        }
        var epoch = selectEpoch(flags & 3);
        if (epoch < 0) {
            dropped++;
            return total;
        }
        var state = readStates.get(epoch);
        var ciphertextOffset = offset + headerLength;
        try {
            var mask = state.cipher13.mask(datagram, ciphertextOffset);
            var header = java.util.Arrays.copyOfRange(datagram, offset, offset + headerLength);
            header[1] ^= mask[0];
            var low = header[1] & 0xFF;
            if (sequenceLength == 2) {
                header[2] ^= mask[1];
                low = low << 8 | (header[2] & 0xFF);
            }
            var sequence = reconstruct(state.window.highest() + 1, low, sequenceLength * 8);
            if (sequence < 0) {
                dropped++;
                return total;
            }
            var inner = state.cipher13.open(sequence, header, datagram, ciphertextOffset, length);
            var end = inner.length - 1;
            while (end >= 0 && inner[end] == 0) {
                end--;
            }
            if (end < 0 || end > MAX_PLAINTEXT) {
                dropped++;
                return total;
            }
            if (!state.window.isFresh(sequence)) {
                dropped++;
                return total;
            }
            state.window.mark(sequence);
            records.add(new Record(inner[end] & 0xFF, epoch, sequence, java.util.Arrays.copyOf(inner, end)));
        } catch (DtlsException exception) {
            dropped++;
            authenticationFailures++;
        }
        return total;
    }

    /// {@return the most recent installed DTLS 1.3 read epoch whose low two bits match, or `-1` for none}
    private long selectEpoch(int bits) {
        var best = -1L;
        for (var entry : readStates.entrySet()) {
            var epoch = entry.getKey();
            if (entry.getValue().cipher13 != null && (epoch & 3) == bits && epoch > best) {
                best = epoch;
            }
        }
        return best;
    }

    /// {@return the full sequence number closest to `expected` whose low `bits` bits are `low`}
    ///
    /// @param expected the expected sequence number, one past the highest authenticated
    /// @param low      the received low bits
    /// @param bits     the number of received bits, 8 or 16
    static long reconstruct(long expected, long low, int bits) {
        var window = 1L << bits;
        var candidate = (expected & ~(window - 1)) | low;
        if (candidate - expected > window / 2 && candidate >= window) {
            candidate -= window;
        } else if (expected - candidate > window / 2) {
            candidate += window;
        }
        return candidate;
    }

    /// The protection and next sequence number of one write epoch.
    private static final class WriteState {
        /// The DTLS 1.2 protection, or `null`.
        private final Dtls12RecordCipher cipher12;

        /// The DTLS 1.3 protection, or `null`.
        private final Dtls13RecordCipher cipher13;

        /// The next sequence number.
        private long nextSequence;

        /// Creates a write state; both ciphers `null` for the plaintext epoch.
        private WriteState(Dtls12RecordCipher cipher12, Dtls13RecordCipher cipher13) {
            this.cipher12 = cipher12;
            this.cipher13 = cipher13;
        }
    }

    /// The protection and replay window of one read epoch.
    private static final class ReadState {
        /// The DTLS 1.2 protection, or `null`.
        private final Dtls12RecordCipher cipher12;

        /// The DTLS 1.3 protection, or `null`.
        private final Dtls13RecordCipher cipher13;

        /// The replay window.
        private final ReplayWindow window = new ReplayWindow();

        /// Creates a read state; both ciphers `null` for the plaintext epoch.
        private ReadState(Dtls12RecordCipher cipher12, Dtls13RecordCipher cipher13) {
            this.cipher12 = cipher12;
            this.cipher13 = cipher13;
        }
    }
}
