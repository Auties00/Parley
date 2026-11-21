package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;

/// The decoded value of one RTP header extension element.
///
/// Each implementation is an immutable record that parses itself from an element value (its static `parse` method)
/// and writes itself back ([#writeTo(ByteBuffer)]); the element id is not part of the value, it is negotiated per
/// session ([HeaderExtensionMap]).
///
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public sealed interface HeaderExtension permits Mid, RtpStreamId, RepairedRtpStreamId, AbsSendTime,
        TransportSequenceNumber, AudioLevel, CsrcAudioLevels, TransmissionTimeOffset, VideoOrientation,
        AbsCaptureTime, PlayoutDelay, VideoContentType, VideoTiming, ColorSpace, DependencyDescriptor {
    /// {@return the URI that identifies the extension}
    URI uri();

    /// {@return the number of bytes [#writeTo(ByteBuffer)] writes}
    int encodedLength();

    /// Writes the element value at the position of `destination` and advances the position past it.
    ///
    /// @param destination the buffer to write into
    /// @throws java.nio.BufferOverflowException if the value does not fit in the remaining bytes
    void writeTo(ByteBuffer destination);

    /// {@return the element value in a new heap buffer, positioned at zero}
    default ByteBuffer encode() {
        var buffer = ByteBuffer.allocate(encodedLength());
        writeTo(buffer);
        return buffer.flip();
    }

    /// Parses the value of an element whose URI is known.
    ///
    /// The dependency descriptor is not parsed here: its frame fields can only be read against the latest template
    /// structure of the stream, so it is read with
    /// [DependencyDescriptor#parse(ByteBuffer, Optional)].
    ///
    /// @param uri   the negotiated URI of the element
    /// @param value the element value between position and limit; it is not modified
    /// @return the value, or empty for an unknown URI or the dependency descriptor
    /// @throws RtpFormatException if the value is malformed for its extension
    static Optional<HeaderExtension> parse(URI uri, ByteBuffer value) throws RtpFormatException {
        Objects.requireNonNull(uri, "uri cannot be null");
        Objects.requireNonNull(value, "value cannot be null");
        var duplicate = value.duplicate();
        var key = uri.toString();
        HeaderExtension result;
        if (key.equals(HeaderExtensionUris.MID.toString())) {
            result = Mid.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.RTP_STREAM_ID.toString())) {
            result = RtpStreamId.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.REPAIRED_RTP_STREAM_ID.toString())) {
            result = RepairedRtpStreamId.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.ABS_SEND_TIME.toString())) {
            result = AbsSendTime.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.TRANSPORT_WIDE_CC.toString())) {
            result = TransportSequenceNumber.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.AUDIO_LEVEL.toString())) {
            result = AudioLevel.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.CSRC_AUDIO_LEVEL.toString())) {
            result = CsrcAudioLevels.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.TOFFSET.toString())) {
            result = TransmissionTimeOffset.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.VIDEO_ORIENTATION.toString())) {
            result = VideoOrientation.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.ABS_CAPTURE_TIME.toString())) {
            result = AbsCaptureTime.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.PLAYOUT_DELAY.toString())) {
            result = PlayoutDelay.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.VIDEO_CONTENT_TYPE.toString())) {
            result = VideoContentType.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.VIDEO_TIMING.toString())) {
            result = VideoTiming.parse(duplicate);
        } else if (key.equals(HeaderExtensionUris.COLOR_SPACE.toString())) {
            result = ColorSpace.parse(duplicate);
        } else {
            result = null;
        }
        return Optional.ofNullable(result);
    }
}
