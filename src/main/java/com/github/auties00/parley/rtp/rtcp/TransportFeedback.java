package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/// Transport-wide congestion control feedback (transport-layer feedback, format 15): the arrival time, or the loss,
/// of every packet of a range of transport-wide sequence numbers, which the sender's congestion controller turns into
/// a delay-based bandwidth estimate.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|  FMT=15 |    PT=205     |           length              |
/// |                     SSRC of packet sender                     |
/// |                      SSRC of media source                     |
/// |      base sequence number     |      packet status count      |
/// |                 reference time                | fb pkt. count |
/// |          packet chunk         |         packet chunk          |
/// .                                                               .
/// |         packet chunk          |  recv delta   |  recv delta   |
/// .                                                               .
/// ```
///
/// Each packet's status is one of "not received", "received with a small delta" (one byte, `0..63.75` ms) or
/// "received with a large or negative delta" (two signed bytes), packed into 16-bit chunks: run-length chunks (one
/// status repeated up to 8191 times) and status vector chunks (fourteen 1-bit or seven 2-bit statuses). Writing picks
/// a run-length chunk for runs of seven or more equal statuses and the densest vector otherwise. Receive deltas are
/// in units of 250 microseconds: a written delta is rounded down to that unit.
///
/// @param senderSsrc        the feedback sender, an unsigned 32-bit value
/// @param mediaSsrc         the media source field; senders write the SSRC of one of the reported streams, but the
///                          transport-wide sequence spans every stream of the transport
/// @param baseSequence      the transport-wide sequence number of the first result, `0..65535`
/// @param referenceTime64ms the arrival time base, a signed 24-bit multiple of 64 milliseconds in the receiver's time
///                          base (`-2^23..2^24 - 1` accepted; parsing yields the signed value)
/// @param feedbackCount     the feedback packet counter, `0..255`, which wraps; a gap tells the sender a feedback
///                          packet was lost
/// @param results           one result per transport-wide sequence number from `baseSequence`, consecutive modulo
///                          65536, `1..65535` of them
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
public record TransportFeedback(long senderSsrc, long mediaSsrc, int baseSequence, long referenceTime64ms,
                                int feedbackCount, List<PacketResult> results) implements RtcpPacket {
    /// The feedback message type of transport-wide feedback.
    public static final int FORMAT = 15;

    /// The most packet statuses a parsed feedback may report: half the sequence space, beyond which the sender could
    /// not tell the range from a wrap, and the bound libwebrtc puts on one feedback (`kMaxReportedPackets`).
    public static final int MAX_STATUS_COUNT = 0x7FFF;

    /// The unit of the receive deltas, in microseconds.
    public static final long DELTA_UNIT_MICROS = 250;

    private static final int NOT_RECEIVED = 0;
    private static final int SMALL_DELTA = 1;
    private static final int LARGE_DELTA = 2;

    /// Validates the fields and copies `results`.
    ///
    /// @throws IllegalArgumentException if a field is out of range, `results` is empty, longer than 65535 or not
    ///                                  consecutive from `baseSequence`, or a delta does not fit 16 signed bits of
    ///                                  250 microseconds
    public TransportFeedback {
        RtcpCodec.checkUint32(senderSsrc, "senderSsrc");
        RtcpCodec.checkUint32(mediaSsrc, "mediaSsrc");
        if (baseSequence < 0 || baseSequence > 0xFFFF) {
            throw new IllegalArgumentException("baseSequence must be in 0..65535: " + baseSequence);
        }
        if (referenceTime64ms < -0x800000 || referenceTime64ms > 0xFFFFFF) {
            throw new IllegalArgumentException("referenceTime64ms must fit 24 bits: " + referenceTime64ms);
        }
        if (feedbackCount < 0 || feedbackCount > 255) {
            throw new IllegalArgumentException("feedbackCount must be in 0..255: " + feedbackCount);
        }
        results = List.copyOf(Objects.requireNonNull(results, "results cannot be null"));
        if (results.isEmpty() || results.size() > 0xFFFF) {
            throw new IllegalArgumentException("results must hold 1..65535 entries: " + results.size());
        }
        for (var i = 0; i < results.size(); i++) {
            var result = results.get(i);
            if (result.transportSequence() != ((baseSequence + i) & 0xFFFF)) {
                throw new IllegalArgumentException("results are not consecutive from the base sequence at " + i);
            }
            symbolOf(result);
        }
    }

    /// The fate of one packet.
    ///
    /// @param transportSequence  the transport-wide sequence number, `0..65535`
    /// @param receiveDeltaMicros the arrival time relative to the previous received packet of the feedback (to the
    ///                           reference time for the first one), in microseconds and a multiple of 250 when parsed;
    ///                           empty when the packet was not received
    public record PacketResult(int transportSequence, OptionalLong receiveDeltaMicros) {
        /// Validates the sequence number.
        ///
        /// @throws IllegalArgumentException if `transportSequence` is out of range
        public PacketResult {
            if (transportSequence < 0 || transportSequence > 0xFFFF) {
                throw new IllegalArgumentException("transportSequence must be in 0..65535: " + transportSequence);
            }
            Objects.requireNonNull(receiveDeltaMicros, "receiveDeltaMicros cannot be null");
        }

        /// {@return a result for a lost packet}
        ///
        /// @param transportSequence the transport-wide sequence number
        public static PacketResult lost(int transportSequence) {
            return new PacketResult(transportSequence, OptionalLong.empty());
        }

        /// {@return a result for a received packet}
        ///
        /// @param transportSequence  the transport-wide sequence number
        /// @param receiveDeltaMicros the arrival delta in microseconds
        public static PacketResult received(int transportSequence, long receiveDeltaMicros) {
            return new PacketResult(transportSequence, OptionalLong.of(receiveDeltaMicros));
        }

        /// {@return whether the packet was received}
        public boolean isReceived() {
            return receiveDeltaMicros.isPresent();
        }
    }

    /// {@return the arrival time of each packet, in microseconds of the receiver's time base: the reference time plus
    /// the running sum of deltas; empty for lost packets}
    public List<OptionalLong> receiveTimesMicros() {
        var out = new ArrayList<OptionalLong>(results.size());
        var time = referenceTime64ms * 64_000;
        for (var result : results) {
            if (result.receiveDeltaMicros().isPresent()) {
                time += result.receiveDeltaMicros().getAsLong();
                out.add(OptionalLong.of(time));
            } else {
                out.add(OptionalLong.empty());
            }
        }
        return List.copyOf(out);
    }

    private static int symbolOf(PacketResult result) {
        if (result.receiveDeltaMicros().isEmpty()) {
            return NOT_RECEIVED;
        }
        var ticks = Math.floorDiv(result.receiveDeltaMicros().getAsLong(), DELTA_UNIT_MICROS);
        if (ticks >= 0 && ticks <= 255) {
            return SMALL_DELTA;
        }
        if (ticks < Short.MIN_VALUE || ticks > Short.MAX_VALUE) {
            throw new IllegalArgumentException("receive delta does not fit 16 bits: "
                    + result.receiveDeltaMicros().getAsLong() + " us");
        }
        return LARGE_DELTA;
    }

    static TransportFeedback parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 16, "transport feedback");
        var sender = RtcpCodec.uint32(body);
        var media = RtcpCodec.uint32(body);
        var base = body.getShort() & 0xFFFF;
        var count = body.getShort() & 0xFFFF;
        var word = body.getInt();
        var reference = (long) (word >> 8);
        var feedbackCount = word & 0xFF;
        if (count == 0) {
            throw new RtcpFormatException("transport feedback with no packet status");
        }
        if (count > MAX_STATUS_COUNT) {
            throw new RtcpFormatException("transport feedback reports more than " + MAX_STATUS_COUNT + " packets: "
                    + count);
        }
        var symbols = new int[count];
        var filled = 0;
        while (filled < count) {
            RtcpCodec.requireRemaining(body, 2, "transport feedback chunk");
            var chunk = body.getShort() & 0xFFFF;
            if ((chunk & 0x8000) == 0) {
                var symbol = (chunk >>> 13) & 0x3;
                var run = chunk & 0x1FFF;
                if (symbol == 3) {
                    throw new RtcpFormatException("transport feedback run of the reserved status");
                }
                for (var i = 0; i < run && filled < count; i++) {
                    symbols[filled++] = symbol;
                }
            } else if ((chunk & 0x4000) == 0) {
                for (var i = 13; i >= 0 && filled < count; i--) {
                    symbols[filled++] = (chunk >>> i) & 0x1;
                }
            } else {
                for (var i = 6; i >= 0 && filled < count; i--) {
                    var symbol = (chunk >>> (2 * i)) & 0x3;
                    if (symbol == 3) {
                        throw new RtcpFormatException("transport feedback vector with the reserved status");
                    }
                    symbols[filled++] = symbol;
                }
            }
        }
        var results = new ArrayList<PacketResult>(count);
        for (var i = 0; i < count; i++) {
            var sequence = (base + i) & 0xFFFF;
            switch (symbols[i]) {
                case SMALL_DELTA -> {
                    RtcpCodec.requireRemaining(body, 1, "transport feedback delta");
                    results.add(PacketResult.received(sequence, (body.get() & 0xFF) * DELTA_UNIT_MICROS));
                }
                case LARGE_DELTA -> {
                    RtcpCodec.requireRemaining(body, 2, "transport feedback delta");
                    results.add(PacketResult.received(sequence, body.getShort() * DELTA_UNIT_MICROS));
                }
                default -> results.add(PacketResult.lost(sequence));
            }
        }
        return new TransportFeedback(sender, media, base, reference, feedbackCount, results);
    }

    /// Encodes the statuses as chunks.
    private short[] chunks(int[] symbols) {
        var out = new ArrayList<Short>();
        var i = 0;
        var n = symbols.length;
        while (i < n) {
            var run = 1;
            while (i + run < n && symbols[i + run] == symbols[i] && run < 0x1FFF) {
                run++;
            }
            if (run >= 7 || i + run == n) {
                out.add((short) (symbols[i] << 13 | run));
                i += run;
                continue;
            }
            var oneBit = true;
            var span = Math.min(14, n - i);
            for (var j = 0; j < span; j++) {
                if (symbols[i + j] > SMALL_DELTA) {
                    oneBit = false;
                    break;
                }
            }
            if (oneBit && (span == 14 || i + span == n)) {
                var chunk = 0x8000;
                for (var j = 0; j < span; j++) {
                    chunk |= symbols[i + j] << (13 - j);
                }
                out.add((short) chunk);
                i += span;
            } else {
                var take = Math.min(7, n - i);
                var chunk = 0xC000;
                for (var j = 0; j < take; j++) {
                    chunk |= symbols[i + j] << (2 * (6 - j));
                }
                out.add((short) chunk);
                i += take;
            }
        }
        var result = new short[out.size()];
        for (var k = 0; k < result.length; k++) {
            result[k] = out.get(k);
        }
        return result;
    }

    private int[] symbols() {
        var symbols = new int[results.size()];
        for (var i = 0; i < symbols.length; i++) {
            symbols[i] = symbolOf(results.get(i));
        }
        return symbols;
    }

    private static int deltaBytes(int[] symbols) {
        var total = 0;
        for (var symbol : symbols) {
            total += symbol == SMALL_DELTA ? 1 : symbol == LARGE_DELTA ? 2 : 0;
        }
        return total;
    }

    @Override
    public int encodedLength() {
        var symbols = symbols();
        return RtcpCodec.padTo4(RtcpCodec.HEADER_LENGTH + 16 + 2 * chunks(symbols).length + deltaBytes(symbols));
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var symbols = symbols();
        var chunks = chunks(symbols);
        var unpadded = RtcpCodec.HEADER_LENGTH + 16 + 2 * chunks.length + deltaBytes(symbols);
        var length = RtcpCodec.padTo4(unpadded);
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        var padding = length - unpadded;
        destination.put((byte) (0x80 | (padding > 0 ? 0x20 : 0) | FORMAT));
        destination.put((byte) TRANSPORT_FEEDBACK);
        destination.putShort((short) (length / 4 - 1));
        destination.putInt((int) senderSsrc);
        destination.putInt((int) mediaSsrc);
        destination.putShort((short) baseSequence);
        destination.putShort((short) results.size());
        destination.putInt((int) ((referenceTime64ms & 0xFFFFFF) << 8 | feedbackCount));
        for (var chunk : chunks) {
            destination.putShort(chunk);
        }
        for (var i = 0; i < symbols.length; i++) {
            if (symbols[i] == NOT_RECEIVED) {
                continue;
            }
            var ticks = Math.floorDiv(results.get(i).receiveDeltaMicros().getAsLong(), DELTA_UNIT_MICROS);
            if (symbols[i] == SMALL_DELTA) {
                destination.put((byte) ticks);
            } else {
                destination.putShort((short) ticks);
            }
        }
        if (padding > 0) {
            for (var i = 1; i < padding; i++) {
                destination.put((byte) 0);
            }
            destination.put((byte) padding);
        }
        return length;
    }
}
