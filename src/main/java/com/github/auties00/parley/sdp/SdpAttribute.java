package com.github.auties00.parley.sdp;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.StringJoiner;

/// A typed `a=` attribute of a session description.
///
/// [#parse(SdpLine)] maps an attribute line to the record of its name, so a reader switches over the closed set of
/// attributes WebRTC uses instead of splitting strings:
///
/// {@snippet lang = java :
/// for (var attribute : section.typedAttributes()) {
///     switch (attribute) {
///         case SdpAttribute.Rtpmap(var pt, var name, var clock, var channels) -> register(pt, name, clock);
///         case SdpAttribute.Mid(var mid) -> bind(mid);
///         case SdpAttribute.Other other -> {}        // an attribute this package does not model
///         case SdpAttribute.Invalid invalid -> {}    // a known attribute with a malformed value
///         default -> {}
///     }
/// }
/// }
///
/// Parsing never fails: an attribute whose name this package does not model becomes [Other], and one whose name it
/// models but whose value is malformed becomes [Invalid], which keeps the text and the reason. Each record writes its
/// canonical line back through [#toLine()]; a [SessionDescription] keeps the original lines anyway, so parsing a
/// description and encoding it again is lossless whatever its attributes hold.
///
/// Every record validates its components on construction and throws [IllegalArgumentException] for a value its
/// grammar rejects.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8840.html RFC 8840: A Session Initiation Protocol (SIP) Usage for Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (Trickle ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8851.html RFC 8851: RTP Payload Format Restrictions
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
/// @spec https://www.rfc-editor.org/rfc/rfc8830.html RFC 8830: WebRTC MediaStream Identification in the Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc5576.html RFC 5576: Source-Specific Media Attributes in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
/// @spec https://www.rfc-editor.org/rfc/rfc8858.html RFC 8858: Indicating Exclusive Support of RTP and RTP Control Protocol (RTCP) Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
/// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
/// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
public sealed interface SdpAttribute {
    /// {@return the attribute name, the text between `a=` and the first colon}
    String attributeName();

    /// {@return the attribute value, the text after the first colon, or an empty optional for a property attribute}
    Optional<String> attributeValue();

    /// {@return the `a=` line of this attribute}
    default SdpLine toLine() {
        return attributeValue()
                .map(value -> SdpLine.attribute(attributeName(), value))
                .orElseGet(() -> SdpLine.flag(attributeName()));
    }

    /// {@return the typed attribute of an `a=` line: the record its name maps to, [Other] for a name this package does
    /// not model, or [Invalid] when the value is malformed}
    ///
    /// @param line the line
    /// @throws IllegalArgumentException if `line` is not an `a=` line
    static SdpAttribute parse(SdpLine line) {
        Objects.requireNonNull(line, "line cannot be null");
        if (line.type() != 'a') {
            throw new IllegalArgumentException("not an attribute line: " + line);
        }
        var name = line.attributeName();
        var value = line.attributeValue();
        try {
            return parse(name, value);
        } catch (IllegalArgumentException exception) {
            return new Invalid(name, value.orElse(""), String.valueOf(exception.getMessage()));
        }
    }

    /// {@return the typed attribute of the text after `a=`, as [#parse(SdpLine)] maps it}
    ///
    /// @param text the attribute text, such as `mid:0` or `rtcp-mux`
    /// @throws IllegalArgumentException if `text` holds a line break
    static SdpAttribute parse(String text) {
        return parse(new SdpLine('a', Objects.requireNonNull(text, "text cannot be null")));
    }

    /// Maps a name and value to its record, throwing for a malformed value.
    private static SdpAttribute parse(String name, Optional<String> value) {
        return switch (name) {
            case "rtpmap" -> Rtpmap.parseValue(required(value));
            case "fmtp" -> Fmtp.parseValue(required(value));
            case "rtcp-fb" -> RtcpFb.parseValue(required(value));
            case "extmap" -> Extmap.parseValue(required(value));
            case "extmap-allow-mixed" -> flag(value, new ExtmapAllowMixed());
            case "ssrc" -> Ssrc.parseValue(required(value));
            case "ssrc-group" -> SsrcGroup.parseValue(required(value));
            case "msid" -> Msid.parseValue(required(value));
            case "mid" -> new Mid(required(value).trim());
            case "group" -> Group.parseValue(required(value));
            case "rid" -> Rid.parseValue(required(value));
            case "simulcast" -> Simulcast.parseValue(required(value));
            case "ice-ufrag" -> new IceUfrag(required(value).trim());
            case "ice-pwd" -> new IcePwd(required(value).trim());
            case "ice-options" -> new IceOptions(List.of(tokens(required(value))));
            case "ice-lite" -> flag(value, new IceLite());
            case "candidate" -> new Candidate(required(value).trim());
            case "end-of-candidates" -> flag(value, new EndOfCandidates());
            case "fingerprint" -> Fingerprint.parseValue(required(value));
            case "setup" -> new Setup(SetupRole.ofSdpName(required(value).trim())
                    .orElseThrow(() -> new IllegalArgumentException("unknown setup role")));
            case "tls-id" -> new TlsId(required(value).trim());
            case "rtcp-mux" -> flag(value, new RtcpMux());
            case "rtcp-mux-only" -> flag(value, new RtcpMuxOnly());
            case "rtcp-rsize" -> flag(value, new RtcpRsize());
            case "rtcp" -> Rtcp.parseValue(required(value));
            case "sctp-port" -> new SctpPort(integer(required(value)));
            case "max-message-size" -> new MaxMessageSize(longInteger(required(value)));
            case "crypto" -> new Crypto(SdesCrypto.parse(required(value)));
            case "cryptex" -> flag(value, new Cryptex());
            case "sendrecv", "sendonly", "recvonly", "inactive" ->
                    flag(value, new Direction(MediaDirection.ofSdpName(name).orElseThrow()));
            case "bundle-only" -> flag(value, new BundleOnly());
            case "ptime" -> new Ptime(integer(required(value)));
            case "maxptime" -> new MaxPtime(integer(required(value)));
            default -> new Other(name, value);
        };
    }

    /// {@return the value of an attribute that requires one}
    private static String required(Optional<String> value) {
        return value.filter(text -> !text.isBlank())
                .orElseThrow(() -> new IllegalArgumentException("missing attribute value"));
    }

    /// {@return the flag record, after checking that the property attribute carries no value}
    private static SdpAttribute flag(Optional<String> value, SdpAttribute attribute) {
        if (value.isPresent()) {
            throw new IllegalArgumentException("property attribute with a value");
        }
        return attribute;
    }

    /// {@return the whitespace-separated tokens of `value`, without empty ones}
    private static String[] tokens(String value) {
        var trimmed = value.trim();
        return trimmed.isEmpty() ? new String[0] : trimmed.split("[ \t]+");
    }

    /// {@return `value` parsed as a decimal `int`}
    private static int integer(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("not an integer: " + value);
        }
    }

    /// {@return `value` parsed as a decimal `long`}
    private static long longInteger(String value) {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("not an integer: " + value);
        }
    }

    /// {@return `value` checked to be a non-empty token without whitespace}
    private static String token(String value, String what) {
        Objects.requireNonNull(value, what + " cannot be null");
        if (value.isEmpty() || value.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("malformed " + what + ": '" + value + "'");
        }
        return value;
    }

    /// {@return the payload type `value` checked to be in `0..127`}
    private static int checkPayloadType(int value) {
        if (value < 0 || value > 127) {
            throw new IllegalArgumentException("payload type out of range: " + value);
        }
        return value;
    }

    /// {@return the SSRC `value` checked to be an unsigned 32-bit number}
    private static long checkSsrc(long value) {
        if (value < 0 || value > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("SSRC out of range: " + value);
        }
        return value;
    }

    /// `a=rtpmap:<pt> <encoding>/<clock>[/<channels>]`, the encoding behind a dynamic RTP payload type.
    ///
    /// @param payloadType  the payload type, `0..127`
    /// @param encodingName the encoding name as written, such as `opus` or `VP8`
    /// @param clockRate    the RTP clock rate in hertz, positive
    /// @param channels     the channel count of an audio encoding, or an empty optional when the line names none
    /// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
    record Rtpmap(int payloadType, String encodingName, int clockRate, OptionalInt channels) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param payloadType  the payload type
        /// @param encodingName the encoding name
        /// @param clockRate    the clock rate
        /// @param channels     the channel count, or an empty optional
        /// @throws IllegalArgumentException if a value is out of range or the name holds `/` or whitespace
        public Rtpmap {
            checkPayloadType(payloadType);
            token(encodingName, "encoding name");
            Objects.requireNonNull(channels, "channels cannot be null");
            if (encodingName.indexOf('/') >= 0) {
                throw new IllegalArgumentException("encoding name holds '/': " + encodingName);
            }
            if (clockRate <= 0 || channels.orElse(1) <= 0) {
                throw new IllegalArgumentException("clock rate and channels must be positive");
            }
        }

        /// Parses the value after `a=rtpmap:`.
        private static Rtpmap parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length != 2) {
                throw new IllegalArgumentException("malformed rtpmap");
            }
            var encoding = tokens[1].split("/", -1);
            if (encoding.length < 2 || encoding.length > 3) {
                throw new IllegalArgumentException("malformed rtpmap encoding");
            }
            return new Rtpmap(integer(tokens[0]), encoding[0], integer(encoding[1]),
                    encoding.length == 3 ? OptionalInt.of(integer(encoding[2])) : OptionalInt.empty());
        }

        @Override
        public String attributeName() {
            return "rtpmap";
        }

        @Override
        public Optional<String> attributeValue() {
            var text = payloadType + " " + encodingName + "/" + clockRate;
            return Optional.of(channels.isPresent() ? text + "/" + channels.getAsInt() : text);
        }
    }

    /// `a=fmtp:<pt> <parameters>`, the format-specific parameters of a payload type.
    ///
    /// Most formats write `key=value` pairs separated by `;`, such as `minptime=10;useinbandfec=1`; some write a bare
    /// value, such as RED's `111/111` or telephone-event's `0-15`, which [#parameterMap()] maps to an empty-valued key.
    ///
    /// @param payloadType the payload type, `0..127`
    /// @param parameters  the parameter text as written, not empty
    /// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
    record Fmtp(int payloadType, String parameters) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param payloadType the payload type
        /// @param parameters  the parameter text
        /// @throws IllegalArgumentException if `payloadType` is out of range or `parameters` is blank
        public Fmtp {
            checkPayloadType(payloadType);
            Objects.requireNonNull(parameters, "parameters cannot be null");
            parameters = parameters.strip();
            if (parameters.isEmpty() || parameters.indexOf('\r') >= 0 || parameters.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("malformed fmtp parameters");
            }
        }

        /// {@return the attribute for `parameters` written as `key=value` pairs separated by `;`, an empty value
        /// written as the bare key}
        ///
        /// @param payloadType the payload type, `0..127`
        /// @param parameters  the parameters, in order; not empty
        /// @throws IllegalArgumentException if `parameters` is empty or `payloadType` is out of range
        public static Fmtp of(int payloadType, Map<String, String> parameters) {
            var joiner = new StringJoiner(";");
            parameters.forEach((key, value) -> joiner.add(value.isEmpty() ? key : key + "=" + value));
            return new Fmtp(payloadType, joiner.toString());
        }

        /// Parses the value after `a=fmtp:`.
        private static Fmtp parseValue(String value) {
            var trimmed = value.strip();
            var space = trimmed.indexOf(' ');
            if (space < 0) {
                throw new IllegalArgumentException("fmtp without parameters");
            }
            return new Fmtp(integer(trimmed.substring(0, space)), trimmed.substring(space + 1));
        }

        /// {@return the unmodifiable parameters in order, keys as written and whitespace trimmed; a parameter without
        /// `=` maps to an empty value}
        public Map<String, String> parameterMap() {
            var result = new LinkedHashMap<String, String>();
            for (var part : parameters.split(";")) {
                var trimmed = part.strip();
                if (trimmed.isEmpty()) {
                    continue;
                }
                var equals = trimmed.indexOf('=');
                if (equals < 0) {
                    result.putIfAbsent(trimmed, "");
                } else {
                    result.putIfAbsent(trimmed.substring(0, equals).strip(), trimmed.substring(equals + 1).strip());
                }
            }
            return Collections.unmodifiableMap(result);
        }

        /// {@return the value of the parameter whose key equals `key` ignoring case, or an empty optional when there
        /// is none}
        ///
        /// @param key the parameter key
        public Optional<String> parameter(String key) {
            Objects.requireNonNull(key, "key cannot be null");
            for (var entry : parameterMap().entrySet()) {
                if (entry.getKey().equalsIgnoreCase(key)) {
                    return Optional.of(entry.getValue());
                }
            }
            return Optional.empty();
        }

        @Override
        public String attributeName() {
            return "fmtp";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(payloadType + " " + parameters);
        }
    }

    /// `a=rtcp-fb:<pt|*> <type> [<parameter>]`, an RTCP feedback mechanism a payload type supports.
    ///
    /// ```text
    /// a=rtcp-fb:96 nack pli      type "nack", parameter "pli"
    /// a=rtcp-fb:* transport-cc   every payload type
    /// ```
    ///
    /// @param payloadType the payload type, or an empty optional for the `*` wildcard
    /// @param type        the feedback type, such as `nack`, `ccm`, `goog-remb` or `transport-cc`
    /// @param parameter   the text after the type, such as `pli` or `fir`, or an empty optional
    /// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
    /// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
    record RtcpFb(OptionalInt payloadType, String type, Optional<String> parameter) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param payloadType the payload type, or an empty optional for `*`
        /// @param type        the feedback type
        /// @param parameter   the parameter, or an empty optional
        /// @throws IllegalArgumentException if the payload type is out of range, `type` is not a token or
        ///                                  `parameter` is blank
        public RtcpFb {
            Objects.requireNonNull(payloadType, "payloadType cannot be null");
            payloadType.ifPresent(SdpAttribute::checkPayloadType);
            token(type, "feedback type");
            Objects.requireNonNull(parameter, "parameter cannot be null");
            parameter = parameter.map(String::strip);
            if (parameter.isPresent() && parameter.get().isEmpty()) {
                throw new IllegalArgumentException("blank feedback parameter");
            }
        }

        /// Parses the value after `a=rtcp-fb:`.
        private static RtcpFb parseValue(String value) {
            var parts = value.strip().split("[ \t]+", 3);
            if (parts.length < 2) {
                throw new IllegalArgumentException("malformed rtcp-fb");
            }
            var pt = parts[0].equals("*") ? OptionalInt.empty() : OptionalInt.of(integer(parts[0]));
            return new RtcpFb(pt, parts[1], parts.length == 3 ? Optional.of(parts[2]) : Optional.empty());
        }

        @Override
        public String attributeName() {
            return "rtcp-fb";
        }

        @Override
        public Optional<String> attributeValue() {
            var pt = payloadType.isPresent() ? String.valueOf(payloadType.getAsInt()) : "*";
            return Optional.of(pt + " " + type + parameter.map(text -> " " + text).orElse(""));
        }
    }

    /// `a=extmap:<id>[/<direction>] <uri> [<attributes>]`, the local identifier of an RTP header extension.
    ///
    /// @param id         the extension identifier: `1..14` fits the one-byte header, `1..255` the two-byte one,
    ///                   and `4096..4351` is the legacy range an answer may use
    /// @param direction  the direction the extension is used in, or an empty optional for the media direction
    /// @param uri        the extension URI, such as `urn:ietf:params:rtp-hdrext:sdes:mid`
    /// @param attributes the extension attributes after the URI, or an empty optional
    /// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
    record Extmap(int id, Optional<MediaDirection> direction, URI uri, Optional<String> attributes)
            implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param id         the extension identifier
        /// @param direction  the direction, or an empty optional
        /// @param uri        the extension URI
        /// @param attributes the extension attributes, or an empty optional
        /// @throws IllegalArgumentException if `id` is out of range or `attributes` is blank
        public Extmap {
            if (!(id >= 1 && id <= 255) && !(id >= 4096 && id <= 4351)) {
                throw new IllegalArgumentException("extension id out of range: " + id);
            }
            Objects.requireNonNull(direction, "direction cannot be null");
            Objects.requireNonNull(uri, "uri cannot be null");
            Objects.requireNonNull(attributes, "attributes cannot be null");
            attributes = attributes.map(String::strip);
            if (attributes.isPresent() && attributes.get().isEmpty()) {
                throw new IllegalArgumentException("blank extension attributes");
            }
        }

        /// Parses the value after `a=extmap:`.
        private static Extmap parseValue(String value) {
            var parts = value.strip().split("[ \t]+", 3);
            if (parts.length < 2) {
                throw new IllegalArgumentException("malformed extmap");
            }
            var slash = parts[0].indexOf('/');
            var id = integer(slash < 0 ? parts[0] : parts[0].substring(0, slash));
            var direction = slash < 0 ? Optional.<MediaDirection>empty()
                    : Optional.of(MediaDirection.ofSdpName(parts[0].substring(slash + 1))
                    .orElseThrow(() -> new IllegalArgumentException("unknown extmap direction")));
            URI uri;
            try {
                uri = new URI(parts[1]);
            } catch (URISyntaxException exception) {
                throw new IllegalArgumentException("malformed extmap URI");
            }
            return new Extmap(id, direction, uri, parts.length == 3 ? Optional.of(parts[2]) : Optional.empty());
        }

        @Override
        public String attributeName() {
            return "extmap";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(id + direction.map(dir -> "/" + dir.sdpName()).orElse("") + " " + uri
                    + attributes.map(text -> " " + text).orElse(""));
        }
    }

    /// `a=extmap-allow-mixed`, which allows one-byte and two-byte header extensions in one RTP stream.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
    record ExtmapAllowMixed() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "extmap-allow-mixed";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=ssrc:<ssrc> <attribute>[:<value>]`, a source-level attribute such as the `cname` of an RTP stream.
    ///
    /// @param ssrc      the synchronization source, an unsigned 32-bit number
    /// @param attribute the source attribute name, such as `cname` or `msid`
    /// @param value     the source attribute value, or an empty optional
    /// @spec https://www.rfc-editor.org/rfc/rfc5576.html RFC 5576: Source-Specific Media Attributes in the Session Description Protocol (SDP)
    record Ssrc(long ssrc, String attribute, Optional<String> value) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param ssrc      the synchronization source
        /// @param attribute the source attribute name
        /// @param value     the source attribute value, or an empty optional
        /// @throws IllegalArgumentException if `ssrc` is not an unsigned 32-bit number or `attribute` is not a token
        public Ssrc {
            checkSsrc(ssrc);
            token(attribute, "source attribute");
            Objects.requireNonNull(value, "value cannot be null");
        }

        /// Parses the value after `a=ssrc:`.
        private static Ssrc parseValue(String value) {
            var parts = value.strip().split("[ \t]+", 2);
            if (parts.length < 2) {
                throw new IllegalArgumentException("malformed ssrc");
            }
            var colon = parts[1].indexOf(':');
            return new Ssrc(longInteger(parts[0]), colon < 0 ? parts[1] : parts[1].substring(0, colon),
                    colon < 0 ? Optional.empty() : Optional.of(parts[1].substring(colon + 1)));
        }

        @Override
        public String attributeName() {
            return "ssrc";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(ssrc + " " + attribute + value.map(text -> ":" + text).orElse(""));
        }
    }

    /// `a=ssrc-group:<semantics> <ssrc>...`, a relationship between sources, such as `FID` (a stream and its RTX
    /// stream), `FEC-FR` (a stream and its FlexFEC stream) or `SIM` (simulcast layers).
    ///
    /// @param semantics the group semantics
    /// @param ssrcs     the sources, at least one, each an unsigned 32-bit number
    /// @spec https://www.rfc-editor.org/rfc/rfc5576.html RFC 5576: Source-Specific Media Attributes in the Session Description Protocol (SDP)
    /// @spec https://www.rfc-editor.org/rfc/rfc5956.html RFC 5956: Forward Error Correction Grouping Semantics in the Session Description Protocol
    record SsrcGroup(String semantics, List<Long> ssrcs) implements SdpAttribute {
        /// The semantics that pairs a media stream with its retransmission stream.
        public static final String FID = "FID";
        /// The semantics that pairs a media stream with its FEC stream.
        public static final String FEC_FR = "FEC-FR";
        /// The semantics that lists simulcast layers.
        public static final String SIM = "SIM";

        /// Creates the attribute, copying the list.
        ///
        /// @param semantics the group semantics
        /// @param ssrcs     the sources
        /// @throws IllegalArgumentException if `semantics` is not a token, `ssrcs` is empty or a source is out of range
        public SsrcGroup {
            token(semantics, "group semantics");
            ssrcs = List.copyOf(ssrcs);
            if (ssrcs.isEmpty()) {
                throw new IllegalArgumentException("empty ssrc-group");
            }
            ssrcs.forEach(SdpAttribute::checkSsrc);
        }

        /// Parses the value after `a=ssrc-group:`.
        private static SsrcGroup parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length < 2) {
                throw new IllegalArgumentException("malformed ssrc-group");
            }
            var ssrcs = new ArrayList<Long>();
            for (var index = 1; index < tokens.length; index++) {
                ssrcs.add(longInteger(tokens[index]));
            }
            return new SsrcGroup(tokens[0], ssrcs);
        }

        @Override
        public String attributeName() {
            return "ssrc-group";
        }

        @Override
        public Optional<String> attributeValue() {
            var joiner = new StringJoiner(" ");
            joiner.add(semantics);
            ssrcs.forEach(ssrc -> joiner.add(Long.toString(ssrc)));
            return Optional.of(joiner.toString());
        }
    }

    /// `a=msid:<stream id> [<track id>]`, the media stream a media section's track belongs to.
    ///
    /// A stream id of `-` means the track belongs to no stream.
    ///
    /// @param streamId the stream id
    /// @param trackId  the track id (the `msid-appdata`), or an empty optional
    /// @spec https://www.rfc-editor.org/rfc/rfc8830.html RFC 8830: WebRTC MediaStream Identification in the Session Description Protocol
    record Msid(String streamId, Optional<String> trackId) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param streamId the stream id
        /// @param trackId  the track id, or an empty optional
        /// @throws IllegalArgumentException if an id is empty, longer than 64 characters or holds whitespace
        public Msid {
            msidToken(streamId);
            Objects.requireNonNull(trackId, "trackId cannot be null");
            trackId.ifPresent(Msid::msidToken);
        }

        /// Checks one msid token: 1 to 64 visible characters.
        private static void msidToken(String value) {
            token(value, "msid id");
            if (value.length() > 64) {
                throw new IllegalArgumentException("msid id longer than 64 characters");
            }
        }

        /// Parses the value after `a=msid:`.
        private static Msid parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length < 1 || tokens.length > 2) {
                throw new IllegalArgumentException("malformed msid");
            }
            return new Msid(tokens[0], tokens.length == 2 ? Optional.of(tokens[1]) : Optional.empty());
        }

        @Override
        public String attributeName() {
            return "msid";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(streamId + trackId.map(id -> " " + id).orElse(""));
        }
    }

    /// `a=mid:<id>`, the identification tag of a media section, which BUNDLE groups and the `sdes:mid` RTP header
    /// extension refer to.
    ///
    /// @param id the tag, 1 to 16 visible characters (the header extension carries at most 16 bytes)
    /// @spec https://www.rfc-editor.org/rfc/rfc5888.html RFC 5888: The Session Description Protocol (SDP) Grouping Framework
    /// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
    record Mid(String id) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param id the tag
        /// @throws IllegalArgumentException if `id` is empty, longer than 16 characters or holds whitespace
        public Mid {
            token(id, "mid");
            if (id.length() > 16) {
                throw new IllegalArgumentException("mid longer than 16 characters");
            }
        }

        @Override
        public String attributeName() {
            return "mid";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(id);
        }
    }

    /// `a=group:<semantics> <mid>...`, a group of media sections, such as a `BUNDLE` group sharing one transport.
    ///
    /// @param semantics the group semantics, such as `BUNDLE` or `LS`
    /// @param mids      the identification tags of the grouped sections, in order; may be empty
    /// @spec https://www.rfc-editor.org/rfc/rfc5888.html RFC 5888: The Session Description Protocol (SDP) Grouping Framework
    /// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
    record Group(String semantics, List<String> mids) implements SdpAttribute {
        /// The BUNDLE semantics.
        public static final String BUNDLE = "BUNDLE";

        /// Creates the attribute, copying the list.
        ///
        /// @param semantics the group semantics
        /// @param mids      the identification tags
        /// @throws IllegalArgumentException if a value is not a token
        public Group {
            token(semantics, "group semantics");
            mids = List.copyOf(mids);
            mids.forEach(mid -> token(mid, "group tag"));
        }

        /// Parses the value after `a=group:`.
        private static Group parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length < 1) {
                throw new IllegalArgumentException("malformed group");
            }
            return new Group(tokens[0], List.of(tokens).subList(1, tokens.length));
        }

        /// {@return whether this is a `BUNDLE` group}
        public boolean isBundle() {
            return BUNDLE.equals(semantics);
        }

        @Override
        public String attributeName() {
            return "group";
        }

        @Override
        public Optional<String> attributeValue() {
            var joiner = new StringJoiner(" ");
            joiner.add(semantics);
            mids.forEach(joiner::add);
            return Optional.of(joiner.toString());
        }
    }

    /// `a=rid:<id> <send|recv> [pt=<pt>,...;<restriction>...]`, an RTP stream identifier with optional payload type
    /// and resolution restrictions, which simulcast layers are named by.
    ///
    /// ```text
    /// a=rid:h send pt=96,97;max-width=1280;max-height=720
    /// ```
    ///
    /// @param id           the stream id, letters, digits, `-` and `_`
    /// @param direction    the direction the stream flows in, from the writer's point of view
    /// @param payloadTypes the payload types the stream may use, empty when unrestricted
    /// @param restrictions the other restrictions in order (`max-width`, `max-fps`, `max-br`, ...), a restriction
    ///                     without a value mapping to an empty string
    /// @spec https://www.rfc-editor.org/rfc/rfc8851.html RFC 8851: RTP Payload Format Restrictions
    record Rid(String id, Direction direction, List<Integer> payloadTypes, Map<String, String> restrictions)
            implements SdpAttribute {
        /// The direction of a stream named by an `a=rid` line.
        public enum Direction {
            /// The writer sends the stream, `send`.
            SEND,
            /// The writer receives the stream, `recv`.
            RECV;

            /// {@return the SDP keyword, `send` or `recv`}
            public String sdpName() {
                return this == SEND ? "send" : "recv";
            }

            /// {@return the other direction}
            public Direction reverse() {
                return this == SEND ? RECV : SEND;
            }
        }

        /// Creates the attribute, copying the collections.
        ///
        /// @param id           the stream id
        /// @param direction    the direction
        /// @param payloadTypes the payload types
        /// @param restrictions the other restrictions
        /// @throws IllegalArgumentException if `id` is not a valid stream id, a payload type is out of range or a
        ///                                  restriction key is not a token
        public Rid {
            validId(id);
            Objects.requireNonNull(direction, "direction cannot be null");
            payloadTypes = List.copyOf(payloadTypes);
            payloadTypes.forEach(SdpAttribute::checkPayloadType);
            var copy = new LinkedHashMap<String, String>();
            restrictions.forEach((key, value) -> {
                token(key, "rid restriction");
                if (key.equals("pt") || key.contains("=") || key.contains(";")) {
                    throw new IllegalArgumentException("malformed rid restriction key: " + key);
                }
                copy.put(key, Objects.requireNonNull(value, "restriction value cannot be null"));
            });
            restrictions = Collections.unmodifiableMap(copy);
        }

        /// {@return whether `id` is a valid stream id: one or more letters, digits, `-` and `_`}
        ///
        /// @param id the candidate stream id
        public static boolean isValidId(String id) {
            Objects.requireNonNull(id, "id cannot be null");
            return !id.isEmpty() && id.chars().allMatch(c -> c < 128 && (Character.isLetterOrDigit(c) || c == '-'
                    || c == '_'));
        }

        /// Checks a stream id.
        private static void validId(String id) {
            if (!isValidId(id)) {
                throw new IllegalArgumentException("malformed rid id: " + id);
            }
        }

        /// Parses the value after `a=rid:`.
        private static Rid parseValue(String value) {
            var parts = value.strip().split("[ \t]+", 3);
            if (parts.length < 2) {
                throw new IllegalArgumentException("malformed rid");
            }
            var direction = switch (parts[1]) {
                case "send" -> Direction.SEND;
                case "recv" -> Direction.RECV;
                default -> throw new IllegalArgumentException("unknown rid direction");
            };
            var payloadTypes = new ArrayList<Integer>();
            var restrictions = new LinkedHashMap<String, String>();
            if (parts.length == 3) {
                for (var param : parts[2].split(";")) {
                    var trimmed = param.strip();
                    if (trimmed.isEmpty()) {
                        continue;
                    }
                    var equals = trimmed.indexOf('=');
                    var key = equals < 0 ? trimmed : trimmed.substring(0, equals);
                    var paramValue = equals < 0 ? "" : trimmed.substring(equals + 1);
                    if (key.equals("pt")) {
                        for (var pt : paramValue.split(",")) {
                            payloadTypes.add(integer(pt));
                        }
                    } else {
                        restrictions.put(key, paramValue);
                    }
                }
            }
            return new Rid(parts[0], direction, payloadTypes, restrictions);
        }

        @Override
        public String attributeName() {
            return "rid";
        }

        @Override
        public Optional<String> attributeValue() {
            var params = new StringJoiner(";");
            if (!payloadTypes.isEmpty()) {
                var pts = new StringJoiner(",");
                payloadTypes.forEach(pt -> pts.add(Integer.toString(pt)));
                params.add("pt=" + pts);
            }
            restrictions.forEach((key, value) -> params.add(value.isEmpty() ? key : key + "=" + value));
            var text = id + " " + direction.sdpName();
            return Optional.of(params.length() == 0 ? text : text + " " + params);
        }
    }

    /// `a=simulcast:[send <streams>] [recv <streams>]`, the simulcast streams of a media section.
    ///
    /// Each direction lists streams separated by `;`; a stream is a list of alternative stream ids separated by `,`,
    /// each prefixed by `~` when it starts paused.
    ///
    /// ```text
    /// a=simulcast:send h;m;~l recv r1,r2
    /// ```
    ///
    /// @param send    the streams the writer sends, each a non-empty list of alternatives; empty when it sends none
    /// @param receive the streams the writer receives, in the same shape
    /// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
    record Simulcast(List<List<Stream>> send, List<List<Stream>> receive) implements SdpAttribute {
        /// One alternative of a simulcast stream.
        ///
        /// @param rid    the stream id an `a=rid` line of the section declares
        /// @param paused whether the stream starts paused (`~`)
        public record Stream(String rid, boolean paused) {
            /// Creates the alternative.
            ///
            /// @param rid    the stream id
            /// @param paused whether the stream starts paused
            /// @throws IllegalArgumentException if `rid` is not a valid stream id
            public Stream {
                Rid.validId(rid);
            }

            /// {@return the alternative as written, `rid` or `~rid`}
            @Override
            public String toString() {
                return paused ? "~" + rid : rid;
            }
        }

        /// Creates the attribute, copying the lists.
        ///
        /// @param send    the sent streams
        /// @param receive the received streams
        /// @throws IllegalArgumentException if both directions are empty or a stream has no alternative
        public Simulcast {
            send = copy(send);
            receive = copy(receive);
            if (send.isEmpty() && receive.isEmpty()) {
                throw new IllegalArgumentException("simulcast without streams");
            }
        }

        /// {@return a send-only simulcast attribute with one unpaused alternative per stream id}
        ///
        /// @param rids the stream ids, in order
        /// @throws IllegalArgumentException if `rids` is empty or one is not a valid stream id
        public static Simulcast sending(List<String> rids) {
            return new Simulcast(rids.stream().map(rid -> List.of(new Stream(rid, false))).toList(), List.of());
        }

        /// Copies a stream list, rejecting a stream without alternatives.
        private static List<List<Stream>> copy(List<List<Stream>> streams) {
            var result = new ArrayList<List<Stream>>();
            for (var alternatives : streams) {
                var copy = List.copyOf(alternatives);
                if (copy.isEmpty()) {
                    throw new IllegalArgumentException("simulcast stream without alternatives");
                }
                result.add(copy);
            }
            return List.copyOf(result);
        }

        /// Parses the value after `a=simulcast:`.
        private static Simulcast parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length != 2 && tokens.length != 4) {
                throw new IllegalArgumentException("malformed simulcast");
            }
            List<List<Stream>> send = List.of();
            List<List<Stream>> receive = List.of();
            for (var index = 0; index < tokens.length; index += 2) {
                var streams = parseStreams(tokens[index + 1]);
                switch (tokens[index]) {
                    case "send" -> {
                        if (!send.isEmpty()) {
                            throw new IllegalArgumentException("duplicate simulcast send");
                        }
                        send = streams;
                    }
                    case "recv" -> {
                        if (!receive.isEmpty()) {
                            throw new IllegalArgumentException("duplicate simulcast recv");
                        }
                        receive = streams;
                    }
                    default -> throw new IllegalArgumentException("unknown simulcast direction");
                }
            }
            return new Simulcast(send, receive);
        }

        /// Parses one `;`-separated stream list.
        private static List<List<Stream>> parseStreams(String text) {
            var result = new ArrayList<List<Stream>>();
            for (var stream : text.split(";", -1)) {
                var alternatives = new ArrayList<Stream>();
                for (var alternative : stream.split(",", -1)) {
                    var paused = alternative.startsWith("~");
                    alternatives.add(new Stream(paused ? alternative.substring(1) : alternative, paused));
                }
                result.add(alternatives);
            }
            return result;
        }

        /// Writes one direction.
        private static String format(List<List<Stream>> streams) {
            var joiner = new StringJoiner(";");
            for (var alternatives : streams) {
                var inner = new StringJoiner(",");
                alternatives.forEach(stream -> inner.add(stream.toString()));
                joiner.add(inner.toString());
            }
            return joiner.toString();
        }

        @Override
        public String attributeName() {
            return "simulcast";
        }

        @Override
        public Optional<String> attributeValue() {
            var joiner = new StringJoiner(" ");
            if (!send.isEmpty()) {
                joiner.add("send").add(format(send));
            }
            if (!receive.isEmpty()) {
                joiner.add("recv").add(format(receive));
            }
            return Optional.of(joiner.toString());
        }
    }

    /// `a=ice-ufrag:<ufrag>`, the ICE username fragment.
    ///
    /// @param ufrag the username fragment, without whitespace
    /// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
    record IceUfrag(String ufrag) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param ufrag the username fragment
        /// @throws IllegalArgumentException if `ufrag` is empty or holds whitespace
        public IceUfrag {
            token(ufrag, "ice-ufrag");
        }

        @Override
        public String attributeName() {
            return "ice-ufrag";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(ufrag);
        }
    }

    /// `a=ice-pwd:<password>`, the ICE password.
    ///
    /// @param password the password, without whitespace
    /// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
    record IcePwd(String password) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param password the password
        /// @throws IllegalArgumentException if `password` is empty or holds whitespace
        public IcePwd {
            token(password, "ice-pwd");
        }

        /// {@return the record without the password}
        @Override
        public String toString() {
            return "IcePwd[password=<redacted>]";
        }

        @Override
        public String attributeName() {
            return "ice-pwd";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(password);
        }
    }

    /// `a=ice-options:<option>...`, the ICE extensions an agent supports, such as `trickle` and `ice2`.
    ///
    /// @param options the option tags, in order, at least one
    /// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
    record IceOptions(List<String> options) implements SdpAttribute {
        /// Creates the attribute, copying the list.
        ///
        /// @param options the option tags
        /// @throws IllegalArgumentException if `options` is empty or a tag is not a token
        public IceOptions {
            options = List.copyOf(options);
            if (options.isEmpty()) {
                throw new IllegalArgumentException("empty ice-options");
            }
            options.forEach(option -> token(option, "ice option"));
        }

        @Override
        public String attributeName() {
            return "ice-options";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(String.join(" ", options));
        }
    }

    /// `a=ice-lite`, which says the writer is an ICE-lite agent.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
    record IceLite() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "ice-lite";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=candidate:<candidate>`, an ICE candidate, kept as the text after `candidate:`.
    ///
    /// @param value the candidate text, such as `1 1 udp 2122260223 192.0.2.4 3480 typ host`
    /// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
    record Candidate(String value) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param value the candidate text
        /// @throws IllegalArgumentException if `value` is blank or spans lines
        public Candidate {
            Objects.requireNonNull(value, "value cannot be null");
            value = value.strip();
            if (value.isEmpty() || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                throw new IllegalArgumentException("malformed candidate");
            }
        }

        @Override
        public String attributeName() {
            return "candidate";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(value);
        }
    }

    /// `a=end-of-candidates`, which says the writer gathers no further candidates for the section.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8840.html RFC 8840: A Session Initiation Protocol (SIP) Usage for Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (Trickle ICE)
    record EndOfCandidates() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "end-of-candidates";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=fingerprint:<hash function> <fingerprint>`, a fingerprint of the certificate the writer's DTLS endpoint
    /// presents.
    ///
    /// @param hashFunction the hash function name in lower case, such as `sha-256`
    /// @param fingerprint  the fingerprint as upper-case hex bytes separated by colons
    /// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
    record Fingerprint(String hashFunction, String fingerprint) implements SdpAttribute {
        /// Creates the attribute, normalising the case of both values.
        ///
        /// @param hashFunction the hash function name
        /// @param fingerprint  the fingerprint
        /// @throws IllegalArgumentException if `hashFunction` is not a token or `fingerprint` is not hex bytes
        ///                                  separated by colons
        public Fingerprint {
            hashFunction = token(hashFunction, "hash function").toLowerCase(Locale.ROOT);
            fingerprint = token(fingerprint, "fingerprint").toUpperCase(Locale.ROOT);
            if (!fingerprint.matches("[0-9A-F]{2}(:[0-9A-F]{2})*")) {
                throw new IllegalArgumentException("malformed fingerprint");
            }
        }

        /// {@return the attribute for a hash function and the digest bytes}
        ///
        /// @param hashFunction the hash function name, such as `sha-256`
        /// @param digest       the digest, at least one byte
        /// @throws IllegalArgumentException if `digest` is empty
        public static Fingerprint of(String hashFunction, byte[] digest) {
            return new Fingerprint(hashFunction, HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest));
        }

        /// Parses the value after `a=fingerprint:`.
        private static Fingerprint parseValue(String value) {
            var tokens = tokens(value);
            if (tokens.length != 2) {
                throw new IllegalArgumentException("malformed fingerprint");
            }
            return new Fingerprint(tokens[0], tokens[1]);
        }

        /// {@return a fresh copy of the digest bytes}
        public byte[] digest() {
            return HexFormat.ofDelimiter(":").parseHex(fingerprint);
        }

        @Override
        public String attributeName() {
            return "fingerprint";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(hashFunction + " " + fingerprint);
        }
    }

    /// `a=setup:<role>`, the DTLS connection role.
    ///
    /// @param role the role
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    record Setup(SetupRole role) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param role the role
        public Setup {
            Objects.requireNonNull(role, "role cannot be null");
        }

        @Override
        public String attributeName() {
            return "setup";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(role.sdpName());
        }
    }

    /// `a=tls-id:<id>`, the identifier of a DTLS association; a new value asks for a new DTLS handshake.
    ///
    /// @param id the identifier, 20 to 255 characters in the specification, accepted here as any token
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    record TlsId(String id) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param id the identifier
        /// @throws IllegalArgumentException if `id` is empty or holds whitespace
        public TlsId {
            token(id, "tls-id");
        }

        @Override
        public String attributeName() {
            return "tls-id";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(id);
        }
    }

    /// `a=rtcp-mux`, which multiplexes RTP and RTCP on one port.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc5761.html RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port
    record RtcpMux() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "rtcp-mux";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=rtcp-mux-only`, which says the writer does not fall back to a separate RTCP port.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8858.html RFC 8858: Indicating Exclusive Support of RTP and RTP Control Protocol (RTCP) Multiplexing Using the Session Description Protocol (SDP)
    record RtcpMuxOnly() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "rtcp-mux-only";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=rtcp-rsize`, which says the writer accepts reduced-size RTCP packets.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc5506.html RFC 5506: Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences
    record RtcpRsize() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "rtcp-rsize";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=rtcp:<port> [<connection address>]`, the RTCP port; WebRTC writes the placeholder `9 IN IP4 0.0.0.0`.
    ///
    /// @param port       the port, `0..65535`
    /// @param connection the network type, address type and address after the port, or an empty optional
    /// @spec https://www.rfc-editor.org/rfc/rfc3605.html RFC 3605: Real Time Control Protocol (RTCP) attribute in Session Description Protocol (SDP)
    record Rtcp(int port, Optional<String> connection) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param port       the port
        /// @param connection the connection address, or an empty optional
        /// @throws IllegalArgumentException if `port` is out of range or `connection` is blank
        public Rtcp {
            if (port < 0 || port > 0xFFFF) {
                throw new IllegalArgumentException("port out of range: " + port);
            }
            Objects.requireNonNull(connection, "connection cannot be null");
            connection = connection.map(String::strip);
            if (connection.isPresent() && connection.get().isEmpty()) {
                throw new IllegalArgumentException("blank rtcp connection");
            }
        }

        /// Parses the value after `a=rtcp:`.
        private static Rtcp parseValue(String value) {
            var parts = value.strip().split("[ \t]+", 2);
            return new Rtcp(integer(parts[0]), parts.length == 2 ? Optional.of(parts[1]) : Optional.empty());
        }

        @Override
        public String attributeName() {
            return "rtcp";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(port + connection.map(text -> " " + text).orElse(""));
        }
    }

    /// `a=sctp-port:<port>`, the SCTP port of a data channel section.
    ///
    /// @param port the port, `1..65535`
    /// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
    record SctpPort(int port) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param port the port
        /// @throws IllegalArgumentException if `port` is outside `1..65535`
        public SctpPort {
            if (port < 1 || port > 0xFFFF) {
                throw new IllegalArgumentException("port out of range: " + port);
            }
        }

        @Override
        public String attributeName() {
            return "sctp-port";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(Integer.toString(port));
        }
    }

    /// `a=max-message-size:<bytes>`, the largest message the writer's SCTP endpoint accepts.
    ///
    /// @param size the size in bytes, at least `0`; `0` means no limit
    /// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
    record MaxMessageSize(long size) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param size the size in bytes
        /// @throws IllegalArgumentException if `size` is negative
        public MaxMessageSize {
            if (size < 0) {
                throw new IllegalArgumentException("negative max-message-size");
            }
        }

        @Override
        public String attributeName() {
            return "max-message-size";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(Long.toString(size));
        }
    }

    /// `a=crypto:<tag> <suite> inline:<key>`, an SDES key.
    ///
    /// @param crypto the parsed key
    /// @spec https://www.rfc-editor.org/rfc/rfc4568.html RFC 4568: Session Description Protocol (SDP) Security Descriptions for Media Streams
    record Crypto(SdesCrypto crypto) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param crypto the key
        public Crypto {
            Objects.requireNonNull(crypto, "crypto cannot be null");
        }

        @Override
        public String attributeName() {
            return "crypto";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(crypto.value());
        }
    }

    /// `a=cryptex`, which encrypts the RTP header extensions and contributing sources of every packet of the
    /// section.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
    record Cryptex() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "cryptex";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=sendrecv`, `a=sendonly`, `a=recvonly` or `a=inactive`, the media direction.
    ///
    /// @param direction the direction
    /// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
    record Direction(MediaDirection direction) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param direction the direction
        public Direction {
            Objects.requireNonNull(direction, "direction cannot be null");
        }

        @Override
        public String attributeName() {
            return direction.sdpName();
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=bundle-only`, which marks an offered section usable only inside its BUNDLE group (its port is `0`).
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
    record BundleOnly() implements SdpAttribute {
        @Override
        public String attributeName() {
            return "bundle-only";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.empty();
        }
    }

    /// `a=ptime:<ms>`, the media duration one packet should carry.
    ///
    /// @param milliseconds the duration, positive
    /// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
    record Ptime(int milliseconds) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param milliseconds the duration
        /// @throws IllegalArgumentException if `milliseconds` is not positive
        public Ptime {
            if (milliseconds <= 0) {
                throw new IllegalArgumentException("ptime must be positive");
            }
        }

        @Override
        public String attributeName() {
            return "ptime";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(Integer.toString(milliseconds));
        }
    }

    /// `a=maxptime:<ms>`, the largest media duration one packet may carry.
    ///
    /// @param milliseconds the duration, positive
    /// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
    record MaxPtime(int milliseconds) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param milliseconds the duration
        /// @throws IllegalArgumentException if `milliseconds` is not positive
        public MaxPtime {
            if (milliseconds <= 0) {
                throw new IllegalArgumentException("maxptime must be positive");
            }
        }

        @Override
        public String attributeName() {
            return "maxptime";
        }

        @Override
        public Optional<String> attributeValue() {
            return Optional.of(Integer.toString(milliseconds));
        }
    }

    /// An attribute whose name this package does not model, kept as written.
    ///
    /// @param name  the attribute name
    /// @param value the attribute value, or an empty optional for a property attribute
    record Other(String name, Optional<String> value) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param name  the attribute name
        /// @param value the attribute value, or an empty optional
        /// @throws IllegalArgumentException if `name` is empty, holds a colon or spans lines
        public Other {
            Objects.requireNonNull(name, "name cannot be null");
            Objects.requireNonNull(value, "value cannot be null");
            if (name.isEmpty() || name.indexOf(':') >= 0 || name.indexOf('\n') >= 0 || name.indexOf('\r') >= 0) {
                throw new IllegalArgumentException("malformed attribute name: " + name);
            }
        }

        @Override
        public String attributeName() {
            return name;
        }

        @Override
        public Optional<String> attributeValue() {
            return value;
        }
    }

    /// An attribute whose name this package models but whose value its grammar rejects, kept as written.
    ///
    /// @param name   the attribute name
    /// @param value  the attribute value as written, empty for a missing one
    /// @param reason why the value was rejected, for diagnostics
    record Invalid(String name, String value, String reason) implements SdpAttribute {
        /// Creates the attribute.
        ///
        /// @param name   the attribute name
        /// @param value  the attribute value
        /// @param reason the rejection reason
        public Invalid {
            Objects.requireNonNull(name, "name cannot be null");
            Objects.requireNonNull(value, "value cannot be null");
            Objects.requireNonNull(reason, "reason cannot be null");
        }

        @Override
        public String attributeName() {
            return name;
        }

        @Override
        public Optional<String> attributeValue() {
            return value.isEmpty() ? Optional.empty() : Optional.of(value);
        }
    }
}
