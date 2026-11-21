package com.github.auties00.parley.mdns;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/// A DNS message as multicast DNS uses it, limited to what `.local` ICE candidates need: questions, and `A` and
/// `AAAA` answer records (other records are kept with raw data).
///
/// ```text
///  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// |                    QDCOUNT                    |
/// |                    ANCOUNT                    |
/// |                    NSCOUNT                    |
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// Names are decoded with compression pointers (loops and forward jumps rejected) and encoded without compression.
/// The top bit of a question's class is the multicast DNS unicast-response (`QU`) bit and that of a record's class
/// the cache-flush bit.
///
/// @param id        the message id, `0` for multicast queries and responses
/// @param response  whether the message is a response (`QR`)
/// @param questions the questions
/// @param answers   the answer records; authority and additional records are not kept
/// @spec https://www.rfc-editor.org/rfc/rfc6762.html RFC 6762: Multicast DNS
/// @spec https://www.rfc-editor.org/rfc/rfc1035.html RFC 1035: Domain Names - Implementation and Specification
record MdnsMessage(int id, boolean response, List<Question> questions, List<Answer> answers) {
    /// The record type of an IPv4 address.
    static final int TYPE_A = 1;

    /// The record type of an IPv6 address.
    static final int TYPE_AAAA = 28;

    /// The query type that matches every record type.
    static final int TYPE_ANY = 255;

    /// The Internet class.
    static final int CLASS_IN = 1;

    /// The largest message decoded or encoded, the 9000 bytes RFC 6762 section 17 allows.
    static final int MAX_LENGTH = 9000;

    /// Creates a message.
    MdnsMessage {
        questions = List.copyOf(questions);
        answers = List.copyOf(answers);
    }

    /// One question.
    ///
    /// @param name            the name, lower-cased, without a trailing dot
    /// @param type            the record type asked for
    /// @param unicastResponse whether the `QU` bit asks for a unicast response
    record Question(String name, int type, boolean unicastResponse) {
        /// Creates a question with a lower-cased name.
        Question {
            name = Objects.requireNonNull(name, "name cannot be null").toLowerCase(Locale.ROOT);
        }
    }

    /// One resource record.
    ///
    /// @param name       the owner name, lower-cased, without a trailing dot
    /// @param type       the record type
    /// @param cacheFlush whether the cache-flush bit is set
    /// @param ttl        the time to live in seconds
    /// @param data       the record data, copied
    record Answer(String name, int type, boolean cacheFlush, long ttl, byte[] data) {
        /// Creates a record with a lower-cased name.
        Answer {
            name = Objects.requireNonNull(name, "name cannot be null").toLowerCase(Locale.ROOT);
            data = data.clone();
        }

        /// {@return an `A` or `AAAA` record for an address}
        static Answer address(String name, InetAddress address, long ttl, boolean cacheFlush) {
            return new Answer(name, address instanceof Inet4Address ? TYPE_A : TYPE_AAAA, cacheFlush, ttl, address.getAddress());
        }

        /// {@return a copy of the record data}
        @Override
        public byte[] data() {
            return data.clone();
        }

        /// {@return the address of an `A` or `AAAA` record whose data has the right length, or `null`}
        InetAddress address() {
            if ((type == TYPE_A && data.length == 4) || (type == TYPE_AAAA && data.length == 16)) {
                try {
                    return InetAddress.getByAddress(data);
                } catch (UnknownHostException exception) {
                    return null;
                }
            }
            return null;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Answer that && name.equals(that.name) && type == that.type
                    && cacheFlush == that.cacheFlush && ttl == that.ttl && java.util.Arrays.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, type, cacheFlush, ttl, java.util.Arrays.hashCode(data));
        }
    }

    /// Decodes a message, its remaining bytes, without moving the buffer.
    ///
    /// @throws MdnsFormatException if the message is truncated or malformed
    static MdnsMessage decode(ByteBuffer packet) throws MdnsFormatException {
        var buffer = packet.slice();
        try {
            if (buffer.remaining() < 12 || buffer.remaining() > MAX_LENGTH) {
                throw new MdnsFormatException("DNS message of " + buffer.remaining() + " bytes");
            }
            var id = buffer.getShort() & 0xFFFF;
            var flags = buffer.getShort() & 0xFFFF;
            var questionCount = buffer.getShort() & 0xFFFF;
            var answerCount = buffer.getShort() & 0xFFFF;
            buffer.getShort();
            buffer.getShort();
            var questions = new ArrayList<Question>(Math.min(questionCount, 64));
            for (var i = 0; i < questionCount; i++) {
                var name = readName(buffer);
                var type = buffer.getShort() & 0xFFFF;
                var questionClass = buffer.getShort() & 0xFFFF;
                questions.add(new Question(name, type, (questionClass & 0x8000) != 0));
            }
            var answers = new ArrayList<Answer>(Math.min(answerCount, 64));
            for (var i = 0; i < answerCount; i++) {
                var name = readName(buffer);
                var type = buffer.getShort() & 0xFFFF;
                var answerClass = buffer.getShort() & 0xFFFF;
                var ttl = Integer.toUnsignedLong(buffer.getInt());
                var length = buffer.getShort() & 0xFFFF;
                if (length > buffer.remaining()) {
                    throw new MdnsFormatException("record data overflows the message");
                }
                var data = new byte[length];
                buffer.get(data);
                answers.add(new Answer(name, type, (answerClass & 0x8000) != 0, ttl, data));
            }
            return new MdnsMessage(id, (flags & 0x8000) != 0, questions, answers);
        } catch (BufferUnderflowException | IndexOutOfBoundsException exception) {
            throw new MdnsFormatException("truncated DNS message", exception);
        }
    }

    /// {@return the message encoded into a new buffer}
    ///
    /// Responses carry the authoritative-answer flag RFC 6762 section 18.4 requires.
    ///
    /// @throws IllegalArgumentException if a label is longer than 63 bytes or the message longer than
    ///                                  [#MAX_LENGTH]
    ByteBuffer encode() {
        var buffer = ByteBuffer.allocate(MAX_LENGTH);
        buffer.putShort((short) id);
        buffer.putShort((short) (response ? 0x8400 : 0));
        buffer.putShort((short) questions.size());
        buffer.putShort((short) answers.size());
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        try {
            for (var question : questions) {
                writeName(buffer, question.name());
                buffer.putShort((short) question.type());
                buffer.putShort((short) (CLASS_IN | (question.unicastResponse() ? 0x8000 : 0)));
            }
            for (var answer : answers) {
                writeName(buffer, answer.name());
                buffer.putShort((short) answer.type());
                buffer.putShort((short) (CLASS_IN | (answer.cacheFlush() ? 0x8000 : 0)));
                buffer.putInt((int) answer.ttl());
                buffer.putShort((short) answer.data.length);
                buffer.put(answer.data);
            }
        } catch (java.nio.BufferOverflowException exception) {
            throw new IllegalArgumentException("DNS message longer than " + MAX_LENGTH + " bytes", exception);
        }
        return buffer.flip();
    }

    /// {@return a name read at the buffer's position, following compression pointers}
    private static String readName(ByteBuffer buffer) throws MdnsFormatException {
        var name = new StringBuilder();
        var position = buffer.position();
        var jumped = false;
        var hops = 0;
        while (true) {
            var length = buffer.get(position) & 0xFF;
            if ((length & 0xC0) == 0xC0) {
                var target = ((length & 0x3F) << 8) | (buffer.get(position + 1) & 0xFF);
                if (target >= position || ++hops > 64) {
                    throw new MdnsFormatException("bad name compression pointer");
                }
                if (!jumped) {
                    buffer.position(position + 2);
                    jumped = true;
                }
                position = target;
                continue;
            }
            if ((length & 0xC0) != 0) {
                throw new MdnsFormatException("unsupported label type");
            }
            if (length == 0) {
                if (!jumped) {
                    buffer.position(position + 1);
                }
                break;
            }
            var label = new byte[length];
            buffer.get(position + 1, label);
            if (!name.isEmpty()) {
                name.append('.');
            }
            name.append(new String(label, StandardCharsets.UTF_8));
            if (name.length() > 255) {
                throw new MdnsFormatException("name longer than 255 characters");
            }
            position += 1 + length;
        }
        return name.toString();
    }

    /// Writes a name as uncompressed labels.
    private static void writeName(ByteBuffer buffer, String name) {
        if (!name.isEmpty()) {
            for (var label : name.split("\\.")) {
                var bytes = label.getBytes(StandardCharsets.UTF_8);
                if (bytes.length == 0 || bytes.length > 63) {
                    throw new IllegalArgumentException("bad DNS label in " + name);
                }
                buffer.put((byte) bytes.length).put(bytes);
            }
        }
        buffer.put((byte) 0);
    }
}
