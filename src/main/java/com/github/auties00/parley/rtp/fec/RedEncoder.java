package com.github.auties00.parley.rtp.fec;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;

/// Builds the RED payloads of an audio stream: each payload carries the new frame as primary and up to `distance`
/// earlier frames as redundancy, the Opus RED scheme browsers use.
///
/// A previous frame is left out when its timestamp offset or its length does not fit its RED header block. An
/// encoder is not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
public final class RedEncoder {
    private final int distance;
    private final Deque<Previous> history = new ArrayDeque<>();

    private record Previous(int payloadType, long timestamp, ByteBuffer data) {
    }

    /// Creates an encoder.
    ///
    /// @param distance how many earlier frames each payload repeats, `0..8`
    /// @throws IllegalArgumentException if `distance` is out of range
    public RedEncoder(int distance) {
        if (distance < 0 || distance > 8) {
            throw new IllegalArgumentException("distance must be in 0..8: " + distance);
        }
        this.distance = distance;
    }

    /// Encodes the next frame.
    ///
    /// @param payloadType the frame's payload type
    /// @param timestamp   the frame's RTP timestamp
    /// @param frame       the frame; its bytes are copied into the history
    /// @return the RED payload, a new heap buffer
    public ByteBuffer encode(int payloadType, long timestamp, ByteBuffer frame) {
        var header = encodeHeader(payloadType, timestamp, frame);
        return ByteBuffer.allocate(header.remaining() + frame.remaining()).put(header).put(frame.duplicate()).flip();
    }

    /// Encodes the part of the next RED payload before the frame itself, the block headers and the redundant copies
    /// of earlier frames ([Red#encodeHeader(List,int)]), and remembers the frame for the next payloads. The payload
    /// is this header followed by `frame`.
    ///
    /// @param payloadType the frame's payload type
    /// @param timestamp   the frame's RTP timestamp
    /// @param frame       the frame, copied into the history when the distance is positive
    /// @return the header, a new buffer
    public ByteBuffer encodeHeader(int payloadType, long timestamp, ByteBuffer frame) {
        var redundant = new ArrayList<Red.Redundant>(history.size());
        for (var previous : history) {
            var offset = (timestamp - previous.timestamp()) & 0xFFFFFFFFL;
            if (offset > 0 && offset <= Red.MAX_TIMESTAMP_OFFSET
                    && previous.data().remaining() <= Red.MAX_BLOCK_LENGTH) {
                redundant.add(new Red.Redundant(previous.payloadType(), (int) offset, previous.data()));
            }
        }
        var header = Red.encodeHeader(redundant, payloadType);
        if (distance > 0) {
            var copy = ByteBuffer.allocate(frame.remaining()).put(frame.duplicate()).flip();
            history.addLast(new Previous(payloadType, timestamp, copy));
            while (history.size() > distance) {
                history.removeFirst();
            }
        }
        return header;
    }

    /// Forgets the history, so the next payload carries no redundancy (after a discontinuity).
    public void reset() {
        history.clear();
    }
}
