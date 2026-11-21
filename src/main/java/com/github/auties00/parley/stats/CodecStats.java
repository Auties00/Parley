package com.github.auties00.parley.stats;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// A codec in use on a transport, `codec`: one per payload type and transport that a stream uses.
///
/// @param id          the identifier of this object
/// @param timestamp   when the object was measured
/// @param payloadType the RTP payload type
/// @param transportId the id of the [TransportStats] the codec is used on
/// @param mimeType    the media type, such as `video/VP8`
/// @param clockRate   the RTP clock rate in hertz, or an empty optional when unknown
/// @param channels    the channel count of an audio codec, or an empty optional
/// @param sdpFmtpLine the `a=fmtp` parameters, or an empty optional when the codec has none
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record CodecStats(String id, Instant timestamp, int payloadType, String transportId, String mimeType,
                         OptionalLong clockRate, OptionalInt channels,
                         Optional<String> sdpFmtpLine) implements RtcStats {
    /// Creates the statistics object.
    public CodecStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(mimeType, "mimeType cannot be null");
        Objects.requireNonNull(clockRate, "clockRate cannot be null");
        Objects.requireNonNull(channels, "channels cannot be null");
        Objects.requireNonNull(sdpFmtpLine, "sdpFmtpLine cannot be null");
    }

    /// {@return `CODEC`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.CODEC;
    }
}
