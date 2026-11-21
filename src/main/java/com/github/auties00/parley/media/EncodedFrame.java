package com.github.auties00.parley.media;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/// One encoded frame, the unit an application's encoder produces and its decoder consumes: an Opus packet, a VP8
/// frame, an H.264 access unit in Annex B byte-stream format, an AV1 temporal unit (or, with a dependency descriptor,
/// the frame of one layer) in low-overhead bitstream format.
///
/// The frame is immutable. Its bytes are a read-only view of the buffer passed in, from that buffer's position to its
/// limit, not a copy: whoever creates a frame hands its bytes over and must not change them afterwards. [#data()]
/// returns a fresh view each time, so reading it never moves another reader's position.
///
/// @param kind         the kind of media; the metadata must describe the same kind
/// @param data         the encoded bytes, read-only
/// @param rtpTimestamp the RTP timestamp of the frame, an unsigned 32-bit value in units of the codec's clock rate
/// @param keyframe     whether the frame decodes without any earlier frame (an intra frame); always `true` for
///                     audio frames from a depacketizer, since every audio frame stands alone
/// @param captureTime  the wall-clock time the frame was captured, when the sender reports it (the
///                     `abs-capture-time` header extension) or the application sets it
/// @param metadata     the per-format metadata
public record EncodedFrame(MediaKind kind, ByteBuffer data, long rtpTimestamp, boolean keyframe,
                           Optional<Instant> captureTime, FrameMetadata metadata) {
    /// Creates a frame.
    ///
    /// @param kind         the kind
    /// @param data         the bytes, from position to limit; the frame keeps a read-only view without copying
    /// @param rtpTimestamp the RTP timestamp
    /// @param keyframe     the keyframe flag
    /// @param captureTime  the capture time
    /// @param metadata     the metadata
    /// @throws IllegalArgumentException if `rtpTimestamp` is outside the unsigned 32-bit range or `metadata`
    ///                                  describes another kind of media
    public EncodedFrame {
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(data, "data cannot be null");
        Objects.requireNonNull(captureTime, "captureTime cannot be null");
        Objects.requireNonNull(metadata, "metadata cannot be null");
        if (rtpTimestamp < 0 || rtpTimestamp > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("RTP timestamp out of range: " + rtpTimestamp);
        }
        if (metadata.kind() != kind) {
            throw new IllegalArgumentException(kind + " frame with " + metadata.kind() + " metadata");
        }
        data = data.slice().asReadOnlyBuffer();
    }

    /// {@return a frame with no capture time and metadata that knows nothing about it}
    ///
    /// The metadata is [AudioFrameMetadata#none()] for audio and [GenericFrameMetadata#none(MediaKind)] for video.
    ///
    /// @param kind         the kind
    /// @param data         the bytes, from position to limit, kept without copying
    /// @param rtpTimestamp the RTP timestamp, an unsigned 32-bit value
    /// @param keyframe     whether the frame decodes on its own
    /// @throws IllegalArgumentException if `rtpTimestamp` is out of range
    public static EncodedFrame of(MediaKind kind, ByteBuffer data, long rtpTimestamp, boolean keyframe) {
        FrameMetadata metadata = kind == MediaKind.AUDIO ? AudioFrameMetadata.none() : GenericFrameMetadata.none(kind);
        return new EncodedFrame(kind, data, rtpTimestamp, keyframe, Optional.empty(), metadata);
    }

    /// {@return a new read-only view of the encoded bytes, positioned at zero}
    @Override
    public ByteBuffer data() {
        return data.duplicate();
    }

    /// {@return the number of encoded bytes}
    public int size() {
        return data.remaining();
    }

    /// {@return a copy of the encoded bytes}
    public byte[] toByteArray() {
        var bytes = new byte[data.remaining()];
        data.get(0, bytes);
        return bytes;
    }

    /// {@return a copy of the frame with other bytes, such as the output of an encryption transform}
    ///
    /// @param newData the bytes, from position to limit, kept without copying
    public EncodedFrame withData(ByteBuffer newData) {
        return new EncodedFrame(kind, newData, rtpTimestamp, keyframe, captureTime, metadata);
    }

    /// {@return a copy of the frame with other metadata}
    ///
    /// @param newMetadata the metadata, of the same kind
    /// @throws IllegalArgumentException if `newMetadata` describes another kind of media
    public EncodedFrame withMetadata(FrameMetadata newMetadata) {
        return new EncodedFrame(kind, data, rtpTimestamp, keyframe, captureTime, newMetadata);
    }

    /// {@return a copy of the frame with a capture time}
    ///
    /// @param time the capture time
    public EncodedFrame withCaptureTime(Instant time) {
        return new EncodedFrame(kind, data, rtpTimestamp, keyframe, Optional.of(time), metadata);
    }

    /// {@return a description of the frame with its size instead of its bytes}
    @Override
    public String toString() {
        return "EncodedFrame[kind=" + kind + ", size=" + data.remaining() + ", rtpTimestamp=" + rtpTimestamp
                + ", keyframe=" + keyframe + ", captureTime=" + captureTime + ", metadata=" + metadata + "]";
    }
}
