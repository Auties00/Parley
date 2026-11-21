package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The transport-wide sequence number of a packet: one counter across every RTP stream of a transport, retransmissions
/// and FEC included, which transport-wide congestion control feedback reports on.
///
/// @param sequence the sequence number, `0..65535`
/// @spec https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01 draft-holmer-rmcat-transport-wide-cc-extensions-01: RTP Extensions for Transport-wide Congestion Control
public record TransportSequenceNumber(int sequence) implements HeaderExtension {
    /// The encoded length.
    public static final int LENGTH = 2;

    /// Validates the range.
    ///
    /// @throws IllegalArgumentException if `sequence` is out of range
    public TransportSequenceNumber {
        if (sequence < 0 || sequence > 0xFFFF) {
            throw new IllegalArgumentException("sequence must be in 0..65535: " + sequence);
        }
    }

    /// Parses an element value.
    ///
    /// @param value the element value; the position is advanced past the two bytes read
    /// @return the sequence number
    /// @throws RtpFormatException if the value is shorter than two bytes
    public static TransportSequenceNumber parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, LENGTH, "transport-wide-cc");
        return new TransportSequenceNumber(value.getShort() & 0xFFFF);
    }

    /// Writes a sequence number into two bytes of a buffer at an absolute index, without moving its position.
    ///
    /// @param destination the buffer, usually a packet whose element was reserved at packetization
    /// @param index       the index of the first value byte
    /// @param sequence    the sequence number; only its low 16 bits are written
    public static void stamp(ByteBuffer destination, int index, int sequence) {
        destination.putShort(index, (short) sequence);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.TRANSPORT_WIDE_CC;
    }

    @Override
    public int encodedLength() {
        return LENGTH;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, LENGTH);
        destination.putShort((short) sequence);
    }
}
