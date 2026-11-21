package com.github.auties00.parley.dtls;

import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/// Rebuilds handshake messages from DTLS fragments and releases them in message sequence order.
///
/// Fragments may overlap, repeat and arrive in any order; a message is released once every byte of it arrived and
/// every earlier message was released. Messages before the next expected one are reported as old, so the caller can
/// treat them as a retransmission by the peer; messages too far ahead are dropped rather than buffered.
///
/// Until the peer's first flight is verified ([#relax()]) only the next expected message is buffered and a hello is
/// capped at [#MAX_HELLO_LENGTH], so an off-path sender cannot make this side hold more than one small message. Memory
/// is only ever allocated for the bytes actually received, never for the length a fragment header claims.
///
/// Instances are not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
final class HandshakeReassembler {
    /// The largest handshake message accepted, which bounds the memory a peer can make this side hold.
    static final int MAX_MESSAGE_LENGTH = 1 << 17;

    /// The largest `ClientHello` or `ServerHello` accepted: these arrive before the peer proved its address, and a
    /// real one is a few hundred bytes.
    static final int MAX_HELLO_LENGTH = 1 << 14;

    /// How many messages beyond the next expected one are buffered once the peer is verified.
    static final int MAX_LOOKAHEAD = 16;

    /// The partial messages, by message sequence number.
    private final Map<Integer, Partial> partials = new HashMap<>();

    /// The next message sequence number to release.
    private int nextReceiveSeq;

    /// Whether only the next expected message is buffered, as before the peer's first flight was verified.
    private boolean strict = true;

    /// What happened to an offered fragment.
    enum Result {
        /// The fragment belongs to the next expected message or a buffered later one.
        ACCEPTED,

        /// The fragment belongs to an already released message.
        OLD,

        /// The fragment was dropped: too far ahead, a hello too large, or inconsistent with earlier fragments.
        DROPPED
    }

    /// {@return the next message sequence number to release}
    int nextReceiveSeq() {
        return nextReceiveSeq;
    }

    /// Allows buffering messages beyond the next expected one, once the peer's first flight was verified (its cookie
    /// checked by a server, its `ServerHello` accepted by a client).
    void relax() {
        strict = false;
    }

    /// Sets the next message sequence number, dropping every buffered fragment before it.
    ///
    /// @param messageSeq the number
    void expect(int messageSeq) {
        nextReceiveSeq = messageSeq;
        partials.keySet().removeIf(seq -> seq < messageSeq);
    }

    /// Offers one fragment.
    ///
    /// @param type           the handshake type
    /// @param length         the full message length
    /// @param messageSeq     the message sequence number
    /// @param fragmentOffset the fragment offset
    /// @param fragment       the fragment bytes
    /// @param epoch          the epoch of the record that carried the fragment; a fragment in a higher epoch than
    ///                       those buffered for its message replaces them, one in a lower epoch is dropped; in
    ///                       the unauthenticated epoch 0 a fragment that disagrees with the buffered ones on the type or
    ///                       length replaces them too, so a forged fragment cannot block the real message
    /// @return what happened to the fragment
    /// @throws DtlsException if the fragment is malformed or the message exceeds [#MAX_MESSAGE_LENGTH]
    Result offer(int type, int length, int messageSeq, int fragmentOffset, byte[] fragment, long epoch)
            throws DtlsException {
        if (length > MAX_MESSAGE_LENGTH) {
            throw new DtlsException(DtlsAlert.ILLEGAL_PARAMETER, "handshake message of " + length + " bytes");
        }
        if (fragmentOffset + fragment.length > length) {
            throw new DtlsException(DtlsAlert.DECODE_ERROR, "handshake fragment beyond its message");
        }
        if (messageSeq < nextReceiveSeq) {
            return Result.OLD;
        }
        if (messageSeq >= nextReceiveSeq + (strict ? 1 : MAX_LOOKAHEAD)) {
            return Result.DROPPED;
        }
        if ((type == HandshakeMessage.CLIENT_HELLO || type == HandshakeMessage.SERVER_HELLO) && length > MAX_HELLO_LENGTH) {
            return Result.DROPPED;
        }
        var partial = partials.get(messageSeq);
        if (partial != null && partial.epoch < epoch) {
            partial = null;
        }
        if (partial == null) {
            partial = new Partial(type, length, epoch);
            partials.put(messageSeq, partial);
        } else if (partial.type != type || partial.length != length || partial.epoch != epoch) {
            if (epoch != 0 || partial.epoch != 0) {
                return Result.DROPPED;
            }
            partial = new Partial(type, length, epoch);
            partials.put(messageSeq, partial);
        }
        partial.add(fragmentOffset, fragment);
        return Result.ACCEPTED;
    }

    /// {@return the next complete message in order, removing it, or an empty optional when it is not complete yet}
    Optional<Received> poll() {
        var partial = partials.get(nextReceiveSeq);
        if (partial == null || !partial.complete()) {
            return Optional.empty();
        }
        partials.remove(nextReceiveSeq);
        return Optional.of(new Received(new HandshakeMessage(partial.type, nextReceiveSeq++, partial.body()), partial.epoch));
    }

    /// A released message with the epoch its fragments arrived in.
    ///
    /// @param message the message
    /// @param epoch   the epoch
    record Received(HandshakeMessage message, long epoch) {
    }

    /// {@return whether a fragment of the next expected message, or of a later one, is buffered}
    boolean hasPending() {
        return !partials.isEmpty();
    }

    /// {@return the fragment bytes buffered across every partial message}
    long bufferedBytes() {
        var total = 0L;
        for (var partial : partials.values()) {
            total += partial.received.cardinality();
        }
        return total;
    }

    /// A message being reassembled. Only the bytes not received yet are kept from each fragment, so the memory held
    /// never exceeds the bytes received; the body is allocated once the message is complete.
    private static final class Partial {
        /// The handshake type.
        private final int type;

        /// The full message length.
        private final int length;

        /// The epoch of the fragments.
        private final long epoch;

        /// Disjoint slices of the body, by offset.
        private final TreeMap<Integer, byte[]> slices = new TreeMap<>();

        /// Which body bytes have arrived.
        private final BitSet received = new BitSet();

        /// Creates an empty partial message.
        private Partial(int type, int length, long epoch) {
            this.type = type;
            this.length = length;
            this.epoch = epoch;
        }

        /// Keeps the bytes of a fragment that were not received yet; overlapping bytes are the same values a correct
        /// peer sends.
        private void add(int offset, byte[] fragment) {
            var end = offset + fragment.length;
            var start = received.nextClearBit(offset);
            while (start < end) {
                var stop = Math.min(end, received.nextSetBit(start) < 0 ? end : received.nextSetBit(start));
                slices.put(start, Arrays.copyOfRange(fragment, start - offset, stop - offset));
                received.set(start, stop);
                start = received.nextClearBit(stop);
            }
        }

        /// {@return whether every byte arrived}
        private boolean complete() {
            return received.cardinality() == length;
        }

        /// {@return the assembled body of a complete message}
        private byte[] body() {
            var body = new byte[length];
            for (var entry : slices.entrySet()) {
                System.arraycopy(entry.getValue(), 0, body, entry.getKey(), entry.getValue().length);
            }
            return body;
        }

        /// {@return a description for debugging}
        @Override
        public String toString() {
            return "Partial[type=" + type + ", received=" + received.cardinality() + "/" + length + "]";
        }
    }
}
