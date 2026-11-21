package com.github.auties00.parley.stats;

import com.github.auties00.parley.media.MediaKind;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// A received RTP stream, `inbound-rtp`, measured by the receiver.
///
/// The frame members are defined for video only and the sample and concealment members for audio only; the members
/// of the other kind are empty. Sample counts are in units of the codec's RTP clock rate (for Opus, 48 kHz samples
/// per channel).
///
/// @param id                             the identifier of this object
/// @param timestamp                      when the object was measured
/// @param ssrc                           the synchronization source of the stream, an unsigned 32-bit number
/// @param kind                           the media kind
/// @param transportId                    the id of the [TransportStats] the stream flows over
/// @param codecId                        the id of the [CodecStats] of the codec in use, or an empty optional before the first packet
/// @param trackIdentifier                the id of the remote track the stream feeds, or an empty optional
/// @param mid                            the identification tag of the media section, or an empty optional
/// @param remoteId                       the id of the matching [RemoteOutboundRtpStreamStats], or an empty optional before the first sender report
/// @param packetsReceived                the RTP packets received, retransmissions excluded
/// @param packetsLost                    the packets expected but not received, as RFC 3550 counts them; may be negative with duplicates
/// @param jitter                         the interarrival jitter, in seconds
/// @param bytesReceived                  the payload bytes received, headers and padding excluded
/// @param headerBytesReceived            the RTP header and padding bytes received
/// @param packetsDiscarded               the packets dropped by the jitter buffer for arriving too late or as duplicates
/// @param fecPacketsReceived             the forward error correction packets received
/// @param fecPacketsDiscarded            the forward error correction packets that recovered nothing
/// @param fecBytesReceived               the forward error correction payload bytes received
/// @param retransmittedPacketsReceived   the retransmitted packets received
/// @param retransmittedBytesReceived     the retransmitted payload bytes received
/// @param rtxSsrc                        the synchronization source of the retransmission stream, or an empty optional
/// @param fecSsrc                        the synchronization source of the FEC stream, or an empty optional
/// @param nackCount                      the NACK packets sent
/// @param firCount                       the full intra requests sent
/// @param pliCount                       the picture loss indications sent
/// @param framesReceived                 the complete video frames assembled, or an empty optional for audio
/// @param keyFramesReceived              the complete video key frames assembled, or an empty optional for audio
/// @param framesDropped                  the video frames dropped before reaching the application, or an empty optional for audio
/// @param frameWidth                     the width of the last frame in pixels, when its payload format carries it
/// @param frameHeight                    the height of the last frame in pixels, when its payload format carries it
/// @param framesPerSecond                the frames received in the last second, or an empty optional for audio
/// @param lastPacketReceivedTimestamp    when the last packet arrived, or an empty optional before the first
/// @param estimatedPlayoutTimestamp      the sender's capture time of the media playing now: the capture time of the
///                                       last frame handed out, advanced by the time since; an empty optional before a
///                                       frame with a known capture time (from `abs-capture-time` or a sender report)
/// @param jitterBufferDelay              the total time frames spent in the jitter buffer, in seconds
/// @param jitterBufferTargetDelay        the sum of the jitter buffer target delays at each emission, in seconds
/// @param jitterBufferMinimumDelay       the sum of the jitter buffer minimum delays at each emission, in seconds
/// @param jitterBufferEmittedCount       the frames (video) or packets (audio) that left the jitter buffer
/// @param totalSamplesReceived           the audio samples played out or concealed, or an empty optional for video
/// @param concealedSamples               the audio samples concealed (lost, late or silent), or an empty optional for video
/// @param silentConcealedSamples         the concealed audio samples that were silence (DTX or comfort noise), or an
///                                       empty optional for video
/// @param concealmentEvents              the runs of concealed audio, or an empty optional for video
/// @param insertedSamplesForDeceleration the audio samples concealed on purpose to grow the delay, or an empty
///                                       optional for video
/// @param removedSamplesForAcceleration  the audio samples skipped on purpose to shrink the delay, or an empty optional
///                                       for video
/// @param audioLevel                     the audio level of the last frame, `0` to `1`, from the `ssrc-audio-level`
///                                       header extension, or an empty optional when unknown or for video
/// @param totalAudioEnergy               the sum over frames of the squared audio level times their duration, or an
///                                       empty optional when unknown or for video
/// @param totalSamplesDuration           the playout time of the samples received, in seconds, or an empty optional for
///                                       video
/// @param playoutId                      the id of the [AudioPlayoutStats] of the stream's playout path, or an empty
///                                       optional for video
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
public record InboundRtpStreamStats(String id, Instant timestamp, long ssrc, MediaKind kind, String transportId,
                                    Optional<String> codecId, Optional<String> trackIdentifier, Optional<String> mid,
                                    Optional<String> remoteId, long packetsReceived, long packetsLost, double jitter,
                                    long bytesReceived, long headerBytesReceived, long packetsDiscarded,
                                    long fecPacketsReceived, long fecPacketsDiscarded, long fecBytesReceived,
                                    long retransmittedPacketsReceived, long retransmittedBytesReceived,
                                    OptionalLong rtxSsrc, OptionalLong fecSsrc, long nackCount, long firCount,
                                    long pliCount, OptionalLong framesReceived, OptionalLong keyFramesReceived,
                                    OptionalLong framesDropped, OptionalInt frameWidth, OptionalInt frameHeight,
                                    OptionalDouble framesPerSecond, Optional<Instant> lastPacketReceivedTimestamp,
                                    Optional<Instant> estimatedPlayoutTimestamp, double jitterBufferDelay,
                                    double jitterBufferTargetDelay, double jitterBufferMinimumDelay,
                                    long jitterBufferEmittedCount, OptionalLong totalSamplesReceived,
                                    OptionalLong concealedSamples, OptionalLong silentConcealedSamples,
                                    OptionalLong concealmentEvents, OptionalLong insertedSamplesForDeceleration,
                                    OptionalLong removedSamplesForAcceleration, OptionalDouble audioLevel,
                                    OptionalDouble totalAudioEnergy, OptionalDouble totalSamplesDuration,
                                    Optional<String> playoutId) implements RtcStats {
    /// Creates the statistics object.
    public InboundRtpStreamStats {
        Objects.requireNonNull(id, "id cannot be null");
        Objects.requireNonNull(timestamp, "timestamp cannot be null");
        Objects.requireNonNull(kind, "kind cannot be null");
        Objects.requireNonNull(transportId, "transportId cannot be null");
        Objects.requireNonNull(codecId, "codecId cannot be null");
        Objects.requireNonNull(trackIdentifier, "trackIdentifier cannot be null");
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(remoteId, "remoteId cannot be null");
        Objects.requireNonNull(rtxSsrc, "rtxSsrc cannot be null");
        Objects.requireNonNull(fecSsrc, "fecSsrc cannot be null");
        Objects.requireNonNull(framesReceived, "framesReceived cannot be null");
        Objects.requireNonNull(keyFramesReceived, "keyFramesReceived cannot be null");
        Objects.requireNonNull(framesDropped, "framesDropped cannot be null");
        Objects.requireNonNull(frameWidth, "frameWidth cannot be null");
        Objects.requireNonNull(frameHeight, "frameHeight cannot be null");
        Objects.requireNonNull(framesPerSecond, "framesPerSecond cannot be null");
        Objects.requireNonNull(lastPacketReceivedTimestamp, "lastPacketReceivedTimestamp cannot be null");
        Objects.requireNonNull(estimatedPlayoutTimestamp, "estimatedPlayoutTimestamp cannot be null");
        Objects.requireNonNull(totalSamplesReceived, "totalSamplesReceived cannot be null");
        Objects.requireNonNull(concealedSamples, "concealedSamples cannot be null");
        Objects.requireNonNull(silentConcealedSamples, "silentConcealedSamples cannot be null");
        Objects.requireNonNull(concealmentEvents, "concealmentEvents cannot be null");
        Objects.requireNonNull(insertedSamplesForDeceleration, "insertedSamplesForDeceleration cannot be null");
        Objects.requireNonNull(removedSamplesForAcceleration, "removedSamplesForAcceleration cannot be null");
        Objects.requireNonNull(audioLevel, "audioLevel cannot be null");
        Objects.requireNonNull(totalAudioEnergy, "totalAudioEnergy cannot be null");
        Objects.requireNonNull(totalSamplesDuration, "totalSamplesDuration cannot be null");
        Objects.requireNonNull(playoutId, "playoutId cannot be null");
    }

    /// {@return `INBOUND_RTP`}
    @Override
    public RtcStatsType type() {
        return RtcStatsType.INBOUND_RTP;
    }
}
