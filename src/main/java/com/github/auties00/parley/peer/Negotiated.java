package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.RtcpFeedback;
import com.github.auties00.parley.sdp.SdpAttribute;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The outcome of an offer/answer exchange, as the JSEP engine hands it to the [PeerBackend]: the transports to run
/// and what flows over each.
///
/// @param offerer    whether this side made the offer
/// @param transports the transports, one per BUNDLE group or unbundled media section
/// @param media      the RTP media sections that are not rejected
/// @param data       the data channel section, or an empty optional when none is negotiated
/// @param closedMids the identification tags of the sections rejected by this exchange, whose streams stop
record Negotiated(boolean offerer, List<Transport> transports, List<Media> media, Optional<Data> data,
                  List<String> closedMids) {
    Negotiated {
        transports = List.copyOf(transports);
        media = List.copyOf(media);
        closedMids = List.copyOf(closedMids);
    }

    /// The local ICE credentials of a transport.
    ///
    /// @param usernameFragment the username fragment
    /// @param password         the password
    record IceCredentials(String usernameFragment, String password) {
        /// {@return the record without the password}
        @Override
        public String toString() {
            return "IceCredentials[usernameFragment=" + usernameFragment + "]";
        }
    }

    /// One transport.
    ///
    /// @param id                 the transport id: the identification tag of the section that carries it
    /// @param mids               the identification tags of the sections that use it
    /// @param local              the local ICE credentials
    /// @param remote             the remote ICE credentials
    /// @param remoteLite         whether the peer is an ICE-lite agent
    /// @param remoteCandidates   the remote candidates signaled in the description, without the `candidate:` prefix
    /// @param remoteComplete     whether the peer signaled the end of its candidates
    /// @param remoteFingerprints the fingerprints the peer's DTLS certificate must match
    /// @param dtlsRole           the local DTLS role
    /// @param iceRole            the local ICE role
    /// @param localTlsId         the `a=tls-id` this side wrote for the transport, kept until its DTLS association
    ///                           restarts
    /// @param remoteTlsId        the `a=tls-id` the peer wrote for the transport, or an empty optional when it wrote
    ///                           none
    /// @param dtlsRestart        whether this exchange asks for a new DTLS association on a transport the previous
    ///                           exchange already ran: the peer changed its `a=tls-id`, its fingerprints or its
    ///                           `a=setup` role (RFC 8842 section 5); the SRTP keys and the SCTP association of the
    ///                           transport restart with it
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    record Transport(String id, List<String> mids, IceCredentials local, IceCredentials remote, boolean remoteLite,
                     List<String> remoteCandidates, boolean remoteComplete,
                     List<SdpAttribute.Fingerprint> remoteFingerprints, DtlsRole dtlsRole, IceRole iceRole,
                     String localTlsId, Optional<String> remoteTlsId, boolean dtlsRestart) {
        Transport {
            mids = List.copyOf(mids);
            remoteCandidates = List.copyOf(remoteCandidates);
            remoteFingerprints = List.copyOf(remoteFingerprints);
        }
    }

    /// A negotiated codec with its payload type.
    ///
    /// @param payloadType    the payload type both sides use
    /// @param codec          the codec
    /// @param feedback       the feedback mechanisms both sides support
    /// @param rtxPayloadType the payload type of its retransmission stream, when RTX is negotiated for it
    record CodecEntry(int payloadType, Codec codec, List<RtcpFeedback> feedback, OptionalInt rtxPayloadType) {
        CodecEntry {
            feedback = List.copyOf(feedback);
        }
    }

    /// One local encoding, with the sources it sends on.
    ///
    /// @param rid      the RTP stream id, or an empty optional without simulcast
    /// @param ssrc     the media source
    /// @param rtxSsrc  the retransmission source, when RTX is negotiated
    /// @param encoding the encoding parameters
    record SendLayer(Optional<String> rid, long ssrc, OptionalLong rtxSsrc, Encoding encoding) {
        /// {@return this layer with `oldSsrc` replaced by `newSsrc` where it is the media or the retransmission
        /// source, or this layer when it uses neither}
        SendLayer withReplacedSsrc(long oldSsrc, long newSsrc) {
            if (ssrc == oldSsrc) {
                return new SendLayer(rid, newSsrc, rtxSsrc, encoding);
            }
            if (rtxSsrc.isPresent() && rtxSsrc.getAsLong() == oldSsrc) {
                return new SendLayer(rid, ssrc, OptionalLong.of(newSsrc), encoding);
            }
            return this;
        }
    }

    /// One remote stream the peer announced.
    ///
    /// @param rid     the RTP stream id, or an empty optional without simulcast
    /// @param ssrc    the media source, when signaled
    /// @param rtxSsrc the retransmission source, when signaled
    /// @param paused  whether the stream starts paused
    record ReceiveLayer(Optional<String> rid, OptionalLong ssrc, OptionalLong rtxSsrc, boolean paused) {
    }

    /// One RTP media section.
    ///
    /// @param transceiver     the transceiver
    /// @param mid             the identification tag
    /// @param transportId     the transport the section uses
    /// @param kind            the media kind
    /// @param direction       the negotiated direction, from this side's point of view
    /// @param codecs          the negotiated media codecs in preference order, the first one sent
    /// @param redPayloadType  the payload type of RED, when negotiated
    /// @param ulpfecPayloadType the payload type of ULPFEC, when negotiated
    /// @param flexfecPayloadType the payload type of FlexFEC, when negotiated
    /// @param telephoneEvent  the telephone-event codec entry, when negotiated
    /// @param extensions      the negotiated header extensions by id
    /// @param reducedSizeRtcp whether both sides accept reduced-size RTCP
    /// @param cname           the local canonical name
    /// @param sendLayers      the local encodings, empty when the section does not send
    /// @param receiveLayers   the remote streams, empty when the section does not receive
    /// @param remoteStreams   the stream ids the remote track belongs to
    /// @param maxBitrate      the payload bitrate in bits per second the peer asks this side to stay under when
    ///                        sending on the section: its `b=TIAS`, else its `b=AS` less an estimate of the IP, UDP,
    ///                        RTP and SRTP overhead (RFC 3890 section 6.2), from the section or else the session
    ///                        level; an empty optional when the peer set no cap
    /// @param cryptex         whether both sides wrote `a=cryptex`, so the RTP header extensions and CSRCs of the
    ///                        section are encrypted (RFC 9335)
    /// @param congestionControlFeedback whether both sides wrote `a=rtcp-fb:* ack ccfb`, so the receiver sends
    ///                        RFC 8888 congestion control feedback
    /// @param extensionDirections the negotiated header extensions by URI, each with its direction from this side's
    ///                        point of view
    /// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
    /// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
    /// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
    record Media(RtpTransceiver transceiver, String mid, String transportId, MediaKind kind,
                 TransceiverDirection direction, List<CodecEntry> codecs, OptionalInt redPayloadType,
                 OptionalInt ulpfecPayloadType, OptionalInt flexfecPayloadType, Optional<CodecEntry> telephoneEvent,
                 Map<Integer, URI> extensions, boolean reducedSizeRtcp, String cname, List<SendLayer> sendLayers,
                 List<ReceiveLayer> receiveLayers, List<String> remoteStreams, OptionalLong maxBitrate,
                 boolean cryptex, boolean congestionControlFeedback,
                 Map<URI, TransceiverDirection> extensionDirections) {
        Media {
            codecs = List.copyOf(codecs);
            extensions = Map.copyOf(extensions);
            extensionDirections = Map.copyOf(extensionDirections);
            sendLayers = List.copyOf(sendLayers);
            receiveLayers = List.copyOf(receiveLayers);
            remoteStreams = List.copyOf(remoteStreams);
        }
    }

    /// The data channel section.
    ///
    /// @param mid                  the identification tag
    /// @param transportId          the transport the section uses
    /// @param localPort            the local SCTP port
    /// @param remotePort           the remote SCTP port
    /// @param localMaxMessageSize  the largest message this side accepts
    /// @param remoteMaxMessageSize the peer's `a=max-message-size`, `0` for no limit; empty when the section has none,
    ///                             which RFC 8841 reads as 64 KiB
    record Data(String mid, String transportId, int localPort, int remotePort, long localMaxMessageSize,
                OptionalLong remoteMaxMessageSize) {
    }
}
