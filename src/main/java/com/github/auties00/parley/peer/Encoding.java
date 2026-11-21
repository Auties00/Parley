package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.Priority;
import com.github.auties00.parley.sdp.SdpAttribute;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalLong;

/// The parameters of one encoding of a sender, the W3C `RTCRtpEncodingParameters`; a simulcast sender has one per
/// layer, each named by its RTP stream id.
///
/// The record is immutable; every `withX` method returns a copy with that component changed:
///
/// {@snippet lang = java :
/// var layers = List.of(
///         Encoding.rid("h").withMaxBitrate(2_500_000),
///         Encoding.rid("m").withScaleResolutionDownBy(2).withMaxBitrate(800_000),
///         Encoding.rid("l").withScaleResolutionDownBy(4).withMaxBitrate(250_000));
/// }
///
/// @param rid                   the RTP stream id of the layer, or an empty optional for a sender with one encoding
/// @param active                whether the encoding is sent; an inactive one stays negotiated but sends nothing
/// @param maxBitrate            the bitrate cap in bits per second, or an empty optional for none
/// @param maxFramerate          the frame rate cap in frames per second, or an empty optional for none
/// @param scaleResolutionDownBy the factor the application should divide the resolution by for this layer, at least
///                              `1`, or an empty optional for `1` (`4`, `2`, `1` by default for three layers)
/// @param priority              the share of the bitrate the encoding gets relative to the others
/// @param networkPriority       the priority whose RFC 8837 DSCP marking the encoding's packets carry
/// @param scalabilityMode       the SVC scalability mode, such as `L1T3`, or an empty optional
/// @param codec                 the negotiated codec this encoding sends, or an empty optional for the first codec
///                              the section negotiated; `setParameters` rejects a codec that was not negotiated
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-svc/ Scalable Video Coding (SVC) Extension for WebRTC
/// @spec https://www.rfc-editor.org/rfc/rfc8851.html RFC 8851: RTP Payload Format Restrictions
/// @spec https://www.rfc-editor.org/rfc/rfc8837.html RFC 8837: Differentiated Services Code Point (DSCP) Packet Markings for WebRTC QoS
public record Encoding(Optional<String> rid, boolean active, OptionalLong maxBitrate, OptionalDouble maxFramerate,
                       OptionalDouble scaleResolutionDownBy, Priority priority, Priority networkPriority,
                       Optional<String> scalabilityMode, Optional<Codec> codec) {
    /// Creates an encoding.
    ///
    /// @param rid                   the RTP stream id, or an empty optional
    /// @param active                whether the encoding is sent
    /// @param maxBitrate            the bitrate cap, or an empty optional
    /// @param maxFramerate          the frame rate cap, or an empty optional
    /// @param scaleResolutionDownBy the resolution divisor, or an empty optional
    /// @param priority              the bitrate priority
    /// @param networkPriority       the network priority
    /// @param scalabilityMode       the scalability mode, or an empty optional
    /// @param codec                 the codec to send, or an empty optional
    /// @throws IllegalArgumentException if `rid` is not a valid RTP stream id, `maxBitrate` or `maxFramerate` is
    ///                                  not positive, `scaleResolutionDownBy` is below `1`, or `scalabilityMode` is
    ///                                  blank
    public Encoding {
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(maxBitrate, "maxBitrate cannot be null");
        Objects.requireNonNull(maxFramerate, "maxFramerate cannot be null");
        Objects.requireNonNull(scaleResolutionDownBy, "scaleResolutionDownBy cannot be null");
        Objects.requireNonNull(priority, "priority cannot be null");
        Objects.requireNonNull(networkPriority, "networkPriority cannot be null");
        Objects.requireNonNull(scalabilityMode, "scalabilityMode cannot be null");
        Objects.requireNonNull(codec, "codec cannot be null");
        if (rid.isPresent() && (!SdpAttribute.Rid.isValidId(rid.get()) || rid.get().length() > 16)) {
            throw new IllegalArgumentException("invalid rid: " + rid.get());
        }
        if (maxBitrate.isPresent() && maxBitrate.getAsLong() <= 0) {
            throw new IllegalArgumentException("maxBitrate must be positive");
        }
        if (maxFramerate.isPresent() && !(maxFramerate.getAsDouble() > 0)) {
            throw new IllegalArgumentException("maxFramerate must be positive");
        }
        if (scaleResolutionDownBy.isPresent() && !(scaleResolutionDownBy.getAsDouble() >= 1)) {
            throw new IllegalArgumentException("scaleResolutionDownBy must be at least 1");
        }
        if (scalabilityMode.isPresent() && scalabilityMode.get().isBlank()) {
            throw new IllegalArgumentException("scalabilityMode cannot be blank");
        }
    }

    /// {@return an active encoding without an RTP stream id, caps, scalability mode or codec, at low priority}
    public static Encoding defaults() {
        return new Encoding(Optional.empty(), true, OptionalLong.empty(), OptionalDouble.empty(),
                OptionalDouble.empty(), Priority.LOW, Priority.LOW, Optional.empty(), Optional.empty());
    }

    /// {@return an active simulcast layer named `rid`, otherwise as [#defaults()]}
    ///
    /// @param rid the RTP stream id, letters, digits, `-` and `_`, at most 16 characters
    /// @throws IllegalArgumentException if `rid` is not a valid RTP stream id
    public static Encoding rid(String rid) {
        return defaults().withRid(rid);
    }

    /// {@return a copy with another RTP stream id}
    ///
    /// @param newRid the RTP stream id
    /// @throws IllegalArgumentException if `newRid` is not a valid RTP stream id
    public Encoding withRid(String newRid) {
        return new Encoding(Optional.of(newRid), active, maxBitrate, maxFramerate, scaleResolutionDownBy, priority,
                networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy that is active or not}
    ///
    /// @param newActive whether the encoding is sent
    public Encoding withActive(boolean newActive) {
        return new Encoding(rid, newActive, maxBitrate, maxFramerate, scaleResolutionDownBy, priority,
                networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy with a bitrate cap}
    ///
    /// @param bitsPerSecond the cap, positive
    /// @throws IllegalArgumentException if `bitsPerSecond` is not positive
    public Encoding withMaxBitrate(long bitsPerSecond) {
        return new Encoding(rid, active, OptionalLong.of(bitsPerSecond), maxFramerate, scaleResolutionDownBy,
                priority, networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy with a frame rate cap}
    ///
    /// @param framesPerSecond the cap, positive
    /// @throws IllegalArgumentException if `framesPerSecond` is not positive
    public Encoding withMaxFramerate(double framesPerSecond) {
        return new Encoding(rid, active, maxBitrate, OptionalDouble.of(framesPerSecond), scaleResolutionDownBy,
                priority, networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy whose resolution is divided by `factor`}
    ///
    /// @param factor the divisor, at least `1`
    /// @throws IllegalArgumentException if `factor` is below `1`
    public Encoding withScaleResolutionDownBy(double factor) {
        return new Encoding(rid, active, maxBitrate, maxFramerate, OptionalDouble.of(factor), priority,
                networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy with another bitrate priority}
    ///
    /// @param newPriority the priority
    public Encoding withPriority(Priority newPriority) {
        return new Encoding(rid, active, maxBitrate, maxFramerate, scaleResolutionDownBy, newPriority,
                networkPriority, scalabilityMode, codec);
    }

    /// {@return a copy with another network priority}
    ///
    /// @param newPriority the priority
    public Encoding withNetworkPriority(Priority newPriority) {
        return new Encoding(rid, active, maxBitrate, maxFramerate, scaleResolutionDownBy, priority, newPriority,
                scalabilityMode, codec);
    }

    /// {@return a copy with an SVC scalability mode}
    ///
    /// @param mode the scalability mode, such as `L1T3`
    /// @throws IllegalArgumentException if `mode` is blank
    public Encoding withScalabilityMode(String mode) {
        return new Encoding(rid, active, maxBitrate, maxFramerate, scaleResolutionDownBy, priority, networkPriority,
                Optional.of(mode), codec);
    }

    /// {@return a copy that sends `newCodec`, which must be one of the codecs the section negotiated}
    ///
    /// @param newCodec the codec
    public Encoding withCodec(Codec newCodec) {
        return new Encoding(rid, active, maxBitrate, maxFramerate, scaleResolutionDownBy, priority, networkPriority,
                scalabilityMode, Optional.of(newCodec));
    }
}
