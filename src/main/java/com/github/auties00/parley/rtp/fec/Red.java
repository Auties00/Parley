package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// The RTP payload format for redundant audio data (RED): one primary encoding preceded by redundant copies of
/// earlier payloads, each described by a header block.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |F|   block PT  |  timestamp offset         |   block length    |  (F = 1, redundant block)
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|   block PT  |                                                  (F = 0, primary block)
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// The same format carries ULPFEC for video (one primary block, the media or the FEC payload, no redundancy).
///
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
public final class Red {
    /// The largest timestamp offset a redundant block can carry.
    public static final int MAX_TIMESTAMP_OFFSET = (1 << 14) - 1;
    /// The largest length a redundant block can carry.
    public static final int MAX_BLOCK_LENGTH = (1 << 10) - 1;

    private Red() {
        throw new AssertionError("Red cannot be instantiated");
    }

    /// One block of a RED payload.
    ///
    /// @param payloadType the block's payload type, `0..127`
    /// @param timestamp   the block's RTP timestamp: the packet's timestamp minus the block's offset
    /// @param data        the block's data, a slice of the RED payload
    /// @param primary     whether the block is the primary encoding
    public record Block(int payloadType, long timestamp, ByteBuffer data, boolean primary) {
    }

    /// A redundant block to encode, older than the primary.
    ///
    /// @param payloadType     the block's payload type
    /// @param timestampOffset the primary timestamp minus the block's, `0..16383`
    /// @param data            the block's data, at most 1023 bytes
    public record Redundant(int payloadType, int timestampOffset, ByteBuffer data) {
    }

    /// Splits a RED payload into its blocks, oldest first and primary last.
    ///
    /// @param payload   the RED payload; it is not modified
    /// @param timestamp the RTP timestamp of the RED packet
    /// @return the blocks, whose data are slices of `payload`
    /// @throws RtpFormatException if the headers or block lengths overrun the payload
    public static List<Block> decode(ByteBuffer payload, long timestamp) throws RtpFormatException {
        var buffer = payload.duplicate();
        var headers = new ArrayList<int[]>();
        while (true) {
            if (!buffer.hasRemaining()) {
                throw new RtpFormatException("RED header list without a primary block");
            }
            var first = buffer.get() & 0xFF;
            if ((first & 0x80) == 0) {
                headers.add(new int[]{first & 0x7F, 0, -1});
                break;
            }
            if (buffer.remaining() < 3) {
                throw new RtpFormatException("truncated RED block header");
            }
            var rest = (buffer.get() & 0xFF) << 16 | (buffer.get() & 0xFF) << 8 | buffer.get() & 0xFF;
            headers.add(new int[]{first & 0x7F, rest >>> 10, rest & 0x3FF});
        }
        var blocks = new ArrayList<Block>(headers.size());
        for (var header : headers) {
            var length = header[2] < 0 ? buffer.remaining() : header[2];
            if (length > buffer.remaining()) {
                throw new RtpFormatException("RED block overruns the payload");
            }
            var data = buffer.slice(buffer.position(), length);
            buffer.position(buffer.position() + length);
            blocks.add(new Block(header[0], (timestamp - header[1]) & 0xFFFFFFFFL, data, header[2] < 0));
        }
        return List.copyOf(blocks);
    }

    /// Encodes a RED payload into a new heap buffer.
    ///
    /// @param redundant          the redundant blocks, oldest first
    /// @param primaryPayloadType the primary block's payload type
    /// @param primary            the primary block's data
    /// @return the payload, positioned at zero
    /// @throws IllegalArgumentException if a redundant block's offset or length does not fit its header
    public static ByteBuffer encode(List<Redundant> redundant, int primaryPayloadType, ByteBuffer primary) {
        var header = encodeHeader(redundant, primaryPayloadType);
        return ByteBuffer.allocate(header.remaining() + primary.remaining()).put(header).put(primary.duplicate())
                .flip();
    }

    /// Writes everything of a RED payload that precedes the primary block's data: the block headers and the
    /// redundant data. A sender writes it and then the primary data into the packet, so the primary block, the bulk
    /// of the payload, is copied once.
    ///
    /// @param redundant          the redundant blocks, oldest first; their data are copied
    /// @param primaryPayloadType the payload type of the primary encoding
    /// @return a new buffer, from position zero to its limit
    /// @throws IllegalArgumentException if a block's timestamp offset or length does not fit its field
    public static ByteBuffer encodeHeader(List<Redundant> redundant, int primaryPayloadType) {
        var length = 1;
        for (var block : redundant) {
            if (block.timestampOffset() < 0 || block.timestampOffset() > MAX_TIMESTAMP_OFFSET) {
                throw new IllegalArgumentException("timestamp offset does not fit 14 bits: "
                        + block.timestampOffset());
            }
            if (block.data().remaining() > MAX_BLOCK_LENGTH) {
                throw new IllegalArgumentException("block length does not fit 10 bits: " + block.data().remaining());
            }
            length += 4 + block.data().remaining();
        }
        var out = ByteBuffer.allocate(length);
        for (var block : redundant) {
            out.put((byte) (0x80 | block.payloadType()));
            var rest = block.timestampOffset() << 10 | block.data().remaining();
            out.put((byte) (rest >>> 16)).put((byte) (rest >>> 8)).put((byte) rest);
        }
        out.put((byte) primaryPayloadType);
        for (var block : redundant) {
            out.put(block.data().duplicate());
        }
        return out.flip();
    }
}
