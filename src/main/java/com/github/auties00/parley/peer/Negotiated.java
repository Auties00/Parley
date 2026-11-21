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
    /// @param iceRestart         whether this exchange restarted ICE on an existing transport
    record Transport(String id, List<String> mids, IceCredentials local, IceCredentials remote, boolean remoteLite,
                     List<String> remoteCandidates, boolean remoteComplete,
                     List<SdpAttribute.Fingerprint> remoteFingerprints, DtlsRole dtlsRole, IceRole iceRole,
                     boolean iceRestart) {
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
    /// @param remoteBitrate   the bandwidth cap the peer set with `b=AS` or `b=TIAS`, in bits per second
    record Media(RtpTransceiver transceiver, String mid, String transportId, MediaKind kind,
                 TransceiverDirection direction, List<CodecEntry> codecs, OptionalInt redPayloadType,
                 OptionalInt ulpfecPayloadType, OptionalInt flexfecPayloadType, Optional<CodecEntry> telephoneEvent,
                 Map<Integer, URI> extensions, boolean reducedSizeRtcp, String cname, List<SendLayer> sendLayers,
                 List<ReceiveLayer> receiveLayers, List<String> remoteStreams, OptionalLong remoteBitrate) {
        Media {
            codecs = List.copyOf(codecs);
            extensions = Map.copyOf(extensions);
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
    /// @param remoteMaxMessageSize the largest message the peer accepts, `0` for no limit
    record Data(String mid, String transportId, int localPort, int remotePort, long localMaxMessageSize,
                long remoteMaxMessageSize) {
    }
}
