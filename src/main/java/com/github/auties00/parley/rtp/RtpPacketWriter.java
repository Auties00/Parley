package com.github.auties00.parley.rtp;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/// Writes one RTP packet (header, CSRCs, RFC 8285 header extension elements, payload and padding) into a buffer the
/// caller owns.
///
/// The writer collects the fields through its chained setters and writes everything in [#finish()]; the setters only
/// keep references, so a payload or extension value buffer must stay unchanged until `finish` returns. A writer is
/// single-use and not thread-safe.
///
/// {@snippet lang = java :
/// var buffer = ByteBuffer.allocate(1500);
/// ByteBuffer packet = RtpPacketWriter.into(buffer)
///         .payloadType(111)
///         .sequence(sequence)
///         .timestamp(timestamp)
///         .ssrc(ssrc)
///         .extension(1, ByteBuffer.wrap(new byte[]{(byte) 0x80 | 30})) // audio level
///         .payload(opusFrame)
///         .finish();
/// }
///
/// # Extension form
///
/// Elements are written in the one-byte form (profile `0xBEDE`) unless [#twoByteExtensions(boolean)] asks for the
/// two-byte form or an element needs it: an id above 14, an empty value, or a value longer than 16 bytes. Mixing the
/// forms across packets of one stream is allowed only when the session negotiated `a=extmap-allow-mixed`; the writer
/// does not know the negotiation, the caller does.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public final class RtpPacketWriter {
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    private final ByteBuffer destination;
    private int payloadType;
    private boolean marker;
    private int sequence;
    private long timestamp;
    private long ssrc;
    private List<Long> csrcs = List.of();
    private int[] extensionIds = new int[4];
    private ByteBuffer[] extensionValues = new ByteBuffer[4];
    private int extensionCount;
    private boolean twoByte;
    private ByteBuffer payload = EMPTY;
    private int padding;
    private boolean finished;

    private RtpPacketWriter(ByteBuffer destination) {
        this.destination = destination;
    }

    /// Creates a writer that writes at the current position of `destination`.
    ///
    /// @param destination the buffer to write into; it must not be read-only
    /// @return a new writer
    /// @throws java.nio.ReadOnlyBufferException if `destination` is read-only
    public static RtpPacketWriter into(ByteBuffer destination) {
        Objects.requireNonNull(destination, "destination cannot be null");
        if (destination.isReadOnly()) {
            throw new java.nio.ReadOnlyBufferException();
        }
        return new RtpPacketWriter(destination);
    }

    /// Sets the payload type.
    ///
    /// @param payloadType the payload type, `0..127`
    /// @return this writer
    /// @throws IllegalArgumentException if `payloadType` is out of range
    public RtpPacketWriter payloadType(int payloadType) {
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException("payloadType must be in 0..127: " + payloadType);
        }
        this.payloadType = payloadType;
        return this;
    }

    /// Sets the marker bit.
    ///
    /// @param marker the marker bit
    /// @return this writer
    public RtpPacketWriter marker(boolean marker) {
        this.marker = marker;
        return this;
    }

    /// Sets the sequence number.
    ///
    /// @param sequence the sequence number, `0..65535`
    /// @return this writer
    /// @throws IllegalArgumentException if `sequence` is out of range
    public RtpPacketWriter sequence(int sequence) {
        if (sequence < 0 || sequence > 0xFFFF) {
            throw new IllegalArgumentException("sequence must be in 0..65535: " + sequence);
        }
        this.sequence = sequence;
        return this;
    }

    /// Sets the RTP timestamp.
    ///
    /// @param timestamp the timestamp, an unsigned 32-bit value
    /// @return this writer
    /// @throws IllegalArgumentException if `timestamp` is out of range
    public RtpPacketWriter timestamp(long timestamp) {
        RtpPacket.checkUint32(timestamp, "timestamp");
        this.timestamp = timestamp;
        return this;
    }

    /// Sets the synchronization source.
    ///
    /// @param ssrc the synchronization source, an unsigned 32-bit value
    /// @return this writer
    /// @throws IllegalArgumentException if `ssrc` is out of range
    public RtpPacketWriter ssrc(long ssrc) {
        RtpPacket.checkUint32(ssrc, "ssrc");
        this.ssrc = ssrc;
        return this;
    }

    /// Sets the contributing sources.
    ///
    /// @param csrcs at most 15 unsigned 32-bit values
    /// @return this writer
    /// @throws IllegalArgumentException if there are more than 15 or one is out of range
    public RtpPacketWriter csrcs(List<Long> csrcs) {
        var copy = List.copyOf(Objects.requireNonNull(csrcs, "csrcs cannot be null"));
        if (copy.size() > 15) {
            throw new IllegalArgumentException("at most 15 CSRCs: " + copy.size());
        }
        for (var csrc : copy) {
            RtpPacket.checkUint32(csrc, "csrc");
        }
        this.csrcs = copy;
        return this;
    }

    /// Adds a header extension element.
    ///
    /// The bytes between the position and the limit of `value` are written; the buffer itself is not modified.
    ///
    /// @param id    the negotiated element id, `1..255`
    /// @param value the element value, at most 255 bytes
    /// @return this writer
    /// @throws IllegalArgumentException if `id` is out of range, already added, or `value` is longer than 255 bytes
    public RtpPacketWriter extension(int id, ByteBuffer value) {
        Objects.requireNonNull(value, "value cannot be null");
        if (id < 1 || id > 255) {
            throw new IllegalArgumentException("extension id must be in 1..255: " + id);
        }
        for (var index = 0; index < extensionCount; index++) {
            if (extensionIds[index] == id) {
                throw new IllegalArgumentException("extension id already added: " + id);
            }
        }
        if (value.remaining() > 255) {
            throw new IllegalArgumentException("extension value longer than 255 bytes: " + value.remaining());
        }
        if (extensionCount == extensionIds.length) {
            extensionIds = Arrays.copyOf(extensionIds, extensionCount * 2);
            extensionValues = Arrays.copyOf(extensionValues, extensionCount * 2);
        }
        extensionIds[extensionCount] = id;
        extensionValues[extensionCount] = value;
        extensionCount++;
        return this;
    }

    /// Forces the two-byte element form even when every element fits the one-byte form.
    ///
    /// @param twoByte whether to force the two-byte form
    /// @return this writer
    public RtpPacketWriter twoByteExtensions(boolean twoByte) {
        this.twoByte = twoByte;
        return this;
    }

    /// Sets the payload.
    ///
    /// The bytes between the position and the limit of `payload` are written; the buffer itself is not modified.
    ///
    /// @param payload the payload
    /// @return this writer
    public RtpPacketWriter payload(ByteBuffer payload) {
        this.payload = Objects.requireNonNull(payload, "payload cannot be null");
        return this;
    }

    /// Sets the number of padding bytes, the count byte included, appended after the payload with the P bit set.
    ///
    /// @param padding `0` for none, or `1..255`
    /// @return this writer
    /// @throws IllegalArgumentException if `padding` is out of range
    public RtpPacketWriter padding(int padding) {
        if (padding < 0 || padding > 255) {
            throw new IllegalArgumentException("padding must be in 0..255: " + padding);
        }
        this.padding = padding;
        return this;
    }

    /// {@return the number of bytes [#finish()] will write with the current fields}
    public int encodedLength() {
        return headerLength() + payload.remaining() + padding;
    }

    private boolean useTwoByte() {
        if (twoByte) {
            return true;
        }
        for (var i = 0; i < extensionCount; i++) {
            var length = extensionValues[i].remaining();
            if (extensionIds[i] > 14 || length == 0 || length > 16) {
                return true;
            }
        }
        return false;
    }

    private int extensionDataLength(boolean twoByteForm) {
        var total = 0;
        for (var i = 0; i < extensionCount; i++) {
            total += (twoByteForm ? 2 : 1) + extensionValues[i].remaining();
        }
        return (total + 3) & ~3;
    }

    private int headerLength() {
        var length = RtpPacket.FIXED_HEADER_LENGTH + 4 * csrcs.size();
        if (extensionCount > 0) {
            length += 4 + extensionDataLength(useTwoByte());
        }
        return length;
    }

    /// Writes the packet at the destination's position and advances the position past it.
    ///
    /// @return a duplicate of the destination positioned at the first byte of the packet with its limit after the
    ///         last; its capacity is the destination's, so the room after the limit is available as tailroom for
    ///         in-place SRTP protection
    /// @throws BufferOverflowException if the packet does not fit in the destination's remaining bytes
    /// @throws IllegalStateException   if the writer already finished
    public ByteBuffer finish() {
        if (finished) {
            throw new IllegalStateException("writer already finished");
        }
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new BufferOverflowException();
        }
        finished = true;
        var start = destination.position();
        var hasExtension = extensionCount > 0;
        var first = 0x80 | (padding > 0 ? 0x20 : 0) | (hasExtension ? 0x10 : 0) | csrcs.size();
        destination.put((byte) first);
        destination.put((byte) ((marker ? 0x80 : 0) | payloadType));
        destination.putShort((short) sequence);
        destination.putInt((int) timestamp);
        destination.putInt((int) ssrc);
        for (var csrc : csrcs) {
            destination.putInt(csrc.intValue());
        }
        if (hasExtension) {
            var twoByteForm = useTwoByte();
            var dataLength = extensionDataLength(twoByteForm);
            destination.putShort((short) (twoByteForm ? RtpPacket.TWO_BYTE_PROFILE : RtpPacket.ONE_BYTE_PROFILE));
            destination.putShort((short) (dataLength / 4));
            var dataStart = destination.position();
            for (var i = 0; i < extensionCount; i++) {
                var value = extensionValues[i];
                var id = extensionIds[i];
                if (twoByteForm) {
                    destination.put((byte) id);
                    destination.put((byte) value.remaining());
                } else {
                    destination.put((byte) (id << 4 | (value.remaining() - 1)));
                }
                put(value);
            }
            while (destination.position() < dataStart + dataLength) {
                destination.put((byte) 0);
            }
        }
        put(payload);
        if (padding > 0) {
            for (var i = 1; i < padding; i++) {
                destination.put((byte) 0);
            }
            destination.put((byte) padding);
        }
        var end = destination.position();
        var view = destination.duplicate();
        view.limit(end);
        view.position(start);
        return view;
    }

    /// Copies the remaining bytes of `source` to the destination's position, advancing only the destination.
    private void put(ByteBuffer source) {
        var length = source.remaining();
        destination.put(destination.position(), source, source.position(), length);
        destination.position(destination.position() + length);
    }
}
