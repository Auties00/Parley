package com.github.auties00.parley.media;

import java.util.Objects;
import java.util.Optional;

/// One RTCP feedback mechanism a codec negotiates, the value of an `a=rtcp-fb` attribute after its payload type.
///
/// @param type      the feedback type, such as `nack`, `ccm`, `goog-remb` or `transport-cc`; never blank
/// @param parameter the feedback parameter, such as `pli` for `nack pli` or `fir` for `ccm fir`, or an empty optional
///                  for none
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public record RtcpFeedback(String type, Optional<String> parameter) {
    /// Generic negative acknowledgement, `nack`.
    public static final RtcpFeedback NACK = new RtcpFeedback("nack", Optional.empty());

    /// Picture loss indication, `nack pli`.
    public static final RtcpFeedback PLI = new RtcpFeedback("nack", Optional.of("pli"));

    /// Full intra request, `ccm fir`.
    public static final RtcpFeedback FIR = new RtcpFeedback("ccm", Optional.of("fir"));

    /// Receiver estimated maximum bitrate, `goog-remb`.
    public static final RtcpFeedback REMB = new RtcpFeedback("goog-remb", Optional.empty());

    /// Transport-wide congestion control feedback, `transport-cc`.
    public static final RtcpFeedback TRANSPORT_CC = new RtcpFeedback("transport-cc", Optional.empty());

    /// Creates a feedback mechanism.
    ///
    /// @param type      the type
    /// @param parameter the parameter
    /// @throws IllegalArgumentException if `type` is blank or contains whitespace, or `parameter` is blank
    public RtcpFeedback {
        Objects.requireNonNull(type, "type cannot be null");
        Objects.requireNonNull(parameter, "parameter cannot be null");
        if (type.isBlank() || type.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("invalid feedback type: " + type);
        }
        if (parameter.isPresent() && parameter.get().isBlank()) {
            throw new IllegalArgumentException("blank feedback parameter");
        }
    }

    /// Parses the feedback part of an `a=rtcp-fb` value, the text after the payload type.
    ///
    /// @param value the feedback, such as `nack pli`
    /// @return the mechanism
    /// @throws IllegalArgumentException if `value` is blank
    public static RtcpFeedback parse(String value) {
        var trimmed = value.strip();
        var space = trimmed.indexOf(' ');
        if (space < 0) {
            return new RtcpFeedback(trimmed, Optional.empty());
        }
        return new RtcpFeedback(trimmed.substring(0, space), Optional.of(trimmed.substring(space + 1).strip()));
    }

    /// {@return the mechanism as an `a=rtcp-fb` value without the payload type, such as `nack pli`}
    @Override
    public String toString() {
        return parameter.map(value -> type + " " + value).orElse(type);
    }
}
