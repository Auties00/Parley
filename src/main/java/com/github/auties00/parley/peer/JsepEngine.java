package com.github.auties00.parley.peer;

import com.github.auties00.parley.dtls.DtlsRole;
import com.github.auties00.parley.ice.IceRole;
import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.media.RtcpFeedback;
import com.github.auties00.parley.sdp.Bandwidth;
import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.MediaDirection;
import com.github.auties00.parley.sdp.Origin;
import com.github.auties00.parley.sdp.RtpCodec;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.sdp.SdpFormatException;
import com.github.auties00.parley.sdp.SdpLine;
import com.github.auties00.parley.sdp.SessionDescription;
import com.github.auties00.parley.sdp.SetupRole;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.Set;

/// The JSEP offer/answer engine of a peer connection: it writes offers and answers from the transceivers, applies
/// local and remote descriptions, runs the signaling state machine and decides what the transports must do.
///
/// The engine works on SDP alone and never touches the network; [PeerConnection] holds its lock around every call and
/// forwards the outcome to the [PeerBackend].
///
/// @implNote This implementation follows RFC 9429 with the choices browsers make where the RFC leaves room: one
/// `a=group:BUNDLE` with every section, the ICE and DTLS attributes repeated in every section, `a=setup:actpass` in
/// every offer, `a=setup:active` in a first answer, a session-wide payload type and header extension id space, and
/// `a=ssrc` lines for a sender without simulcast. Every transport section carries an `a=tls-id`, one value for all
/// the sections of the offered BUNDLE group, kept until the peer restarts the DTLS association. Every RTP section of
/// an offer carries `a=cryptex` and `a=rtcp-fb:* ack ccfb`, which an answer echoes when offered: RFC 9335 and RFC 8888
/// make each inert unless both sides write it, so neither needs a configuration toggle.
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
/// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
/// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
/// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
final class JsepEngine {
    /// The RTP profile of every media section Parley writes.
    static final String RTP_PROTOCOL = "UDP/TLS/RTP/SAVPF";
    /// The protocol of the data section Parley writes.
    static final String SCTP_PROTOCOL = "UDP/DTLS/SCTP";
    /// The SCTP port Parley uses, the one every browser uses.
    static final int SCTP_PORT = 5000;
    /// The largest message Parley accepts, the value browsers advertise.
    static final long MAX_MESSAGE_SIZE = 262144;
    /// The `a=max-message-size` a section without the attribute implies.
    static final long DEFAULT_REMOTE_MAX_MESSAGE_SIZE = 65536;
    /// The characters of an ICE username fragment or password.
    private static final String ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    /// The length of a generated `a=tls-id`, within the 20 to 255 characters RFC 8842 allows.
    private static final int TLS_ID_LENGTH = 32;
    /// The bytes an RTP packet carries beyond its payload: IPv4 (20), UDP (8), the fixed RTP header (12) and the
    /// SRTP authentication tag (10), the overhead an `AS` bandwidth includes and a `TIAS` one does not.
    static final int PACKET_OVERHEAD_BYTES = 50;
    /// The packet rate assumed for an audio section when converting `AS` to a payload rate: one packet per 20 ms.
    static final int AUDIO_PACKETS_PER_SECOND = 50;
    /// The packet size assumed for a video section when converting `AS` to a payload rate.
    static final int VIDEO_PACKET_BYTES = 1200;
    /// The RTP profiles of DTLS-SRTP, the only ones a peer connection negotiates (RFC 9429 section 5.1.2).
    private static final Set<String> DTLS_SRTP_PROTOCOLS = Set.of("UDP/TLS/RTP/SAVPF", "UDP/TLS/RTP/SAVP",
            "TCP/DTLS/RTP/SAVPF", "TCP/DTLS/RTP/SAVP");

    /// A description with its type, parsed.
    record Description(JsepType type, SessionDescription sdp) {
    }

    /// One media section of an offer being written.
    ///
    /// @param kind        the media type of the section: `audio`, `video` or `application`
    /// @param transceiver the transceiver, or `null` for the data section and dead sections
    /// @param mid         the identification tag
    /// @param rejected    whether the section is rejected (port 0)
    /// @param data        whether this is the data section
    /// @param previous    the section as last negotiated, for a dead section, or `null`
    private record Slot(String kind, RtpTransceiver transceiver, String mid, boolean rejected, boolean data,
                        MediaDescription previous) {
    }

    /// What a rollback restores.
    private record Snapshot(List<RtpTransceiver> transceivers, Map<RtpTransceiver, Object[]> fields, String dataMid,
                            Negotiated.IceCredentials localIce, Map<String, Integer> payloadTypes,
                            Map<URI, Integer> extensionIds, Map<String, String> localTransportOf) {
    }

    /// The connection.
    private final PeerConnection connection;
    /// The source of ids and credentials.
    private final SecureRandom random = new SecureRandom();
    /// The session id of every description.
    private final String sessionId;
    /// The canonical name of the RTCP streams.
    private final String cname;
    /// The session version of the last created description.
    private long sessionVersion = 1;
    /// The body of the last created description without its `o=` line, to tell whether the next one differs.
    private String lastCreatedBody;

    /// The signaling state.
    private SignalingState state = SignalingState.STABLE;
    /// The current local description, or `null`.
    private Description currentLocal;
    /// The pending local description, or `null`.
    private Description pendingLocal;
    /// The current remote description, or `null`.
    private Description currentRemote;
    /// The pending remote description, or `null`.
    private Description pendingRemote;
    /// The text of the last created offer, or `null`.
    private String lastCreatedOffer;
    /// The text of the last created answer, or `null`.
    private String lastCreatedAnswer;
    /// The transceiver each new identification tag of the last created offer was given to.
    private Map<String, RtpTransceiver> lastOfferAssignments = Map.of();

    /// The local ICE credentials of the last applied local description, or `null`.
    private Negotiated.IceCredentials localIce;
    /// The credentials the next local description uses when it does not keep [#localIce], or `null`.
    private Negotiated.IceCredentials nextIce;
    /// Whether the application asked for an ICE restart.
    private boolean iceRestartRequested;
    /// The local DTLS role once a first answer decided it, or `null`.
    private DtlsRole dtlsRole;
    /// The local ICE role once a first answer decided it, or `null`.
    private IceRole iceRole;
    /// Whether the application created a data channel.
    private boolean dataRequested;
    /// The identification tag of the data section, or `null`.
    private String dataMid;
    /// The payload type of each codec configuration, session-wide.
    private Map<String, Integer> payloadTypes = new HashMap<>();
    /// The identifier of each header extension, session-wide.
    private Map<URI, Integer> extensionIds = new HashMap<>();
    /// The local transport of each identification tag in the last applied local description.
    private Map<String, String> localTransportOf = new HashMap<>();
    /// The transports gathering, with the credentials they gather with.
    private final Map<String, Negotiated.IceCredentials> gathering = new HashMap<>();
    /// The local candidates of each transport, without the `candidate:` prefix.
    private final Map<String, List<String>> localCandidates = new LinkedHashMap<>();
    /// The transports that finished gathering.
    private final Set<String> localComplete = new HashSet<>();
    /// The trickled remote candidates of each section.
    private final Map<String, List<String>> remoteCandidates = new LinkedHashMap<>();
    /// The sections whose trickled candidates ended.
    private final Set<String> remoteComplete = new HashSet<>();
    /// The last negotiation applied, or `null`.
    private Negotiated negotiated;
    /// The `a=tls-id` of each local transport written by a created description that no applied local description
    /// carries yet; cleared when a local description is applied, whose own values then hold.
    private final Map<String, String> freshTlsIds = new HashMap<>();
    /// What a rollback restores, captured when the state leaves `STABLE`.
    private Snapshot stable;

    /// Creates the engine of `connection`.
    JsepEngine(PeerConnection connection) {
        this.connection = connection;
        this.sessionId = Long.toUnsignedString(random.nextLong() >>> 2);
        this.cname = randomToken(16);
    }

    /// {@return the signaling state}
    SignalingState state() {
        return state;
    }

    /// {@return the canonical name of the RTCP streams}
    String cname() {
        return cname;
    }

    /// {@return the last negotiation applied, or an empty optional before the first answer}
    Optional<Negotiated> negotiated() {
        return Optional.ofNullable(negotiated);
    }

    /// Marks the connection closed.
    void close() {
        state = SignalingState.CLOSED;
    }

    /// Requests an ICE restart at the next offer.
    void requestIceRestart() {
        iceRestartRequested = true;
    }

    /// Records that the application created a data channel.
    void requestData() {
        dataRequested = true;
    }


    /// {@return the pending local description if any, else the current one, with the gathered candidates}
    Optional<JsepDescription> localDescription() {
        return render(pendingLocal != null ? pendingLocal : currentLocal, true);
    }

    /// {@return the current local description with the gathered candidates}
    Optional<JsepDescription> currentLocalDescription() {
        return render(currentLocal, true);
    }

    /// {@return the pending local description with the gathered candidates}
    Optional<JsepDescription> pendingLocalDescription() {
        return render(pendingLocal, true);
    }

    /// {@return the pending remote description if any, else the current one, with the trickled candidates}
    Optional<JsepDescription> remoteDescription() {
        return render(pendingRemote != null ? pendingRemote : currentRemote, false);
    }

    /// {@return the current remote description with the trickled candidates}
    Optional<JsepDescription> currentRemoteDescription() {
        return render(currentRemote, false);
    }

    /// {@return the pending remote description with the trickled candidates}
    Optional<JsepDescription> pendingRemoteDescription() {
        return render(pendingRemote, false);
    }

    /// Adds the candidates gathered or trickled so far to a description.
    private Optional<JsepDescription> render(Description description, boolean local) {
        if (description == null) {
            return Optional.empty();
        }
        var sections = new ArrayList<MediaDescription>();
        var written = new HashSet<String>();
        for (var section : description.sdp().media()) {
            var mid = section.mid().orElse(null);
            if (mid == null || section.isRejected()) {
                sections.add(section);
                continue;
            }
            var lines = new ArrayList<>(section.lines());
            var present = new HashSet<>(section.attributes("candidate"));
            if (local) {
                var transport = localTransportOf.get(mid);
                if (transport != null && transport.equals(mid) && written.add(transport)) {
                    for (var candidate : localCandidates.getOrDefault(transport, List.of())) {
                        if (present.add(candidate)) {
                            lines.add(SdpLine.attribute("candidate", candidate));
                        }
                    }
                    if (localComplete.contains(transport) && !section.hasAttribute("end-of-candidates")) {
                        lines.add(SdpLine.flag("end-of-candidates"));
                    }
                }
            } else {
                for (var candidate : remoteCandidates.getOrDefault(mid, List.of())) {
                    if (present.add(candidate)) {
                        lines.add(SdpLine.attribute("candidate", candidate));
                    }
                }
                if (remoteComplete.contains(mid) && !section.hasAttribute("end-of-candidates")) {
                    lines.add(SdpLine.flag("end-of-candidates"));
                }
            }
            sections.add(section.withLines(lines));
        }
        return Optional.of(new JsepDescription(description.type(), description.sdp().withMedia(sections).encode()));
    }


    /// Writes an offer from the transceivers, the data channel request and the negotiated state.
    ///
    /// @throws InvalidStateException if the signaling state is neither `STABLE` nor `HAVE_LOCAL_OFFER`
    JsepDescription createOffer(OfferOptions options) {
        if (state != SignalingState.STABLE && state != SignalingState.HAVE_LOCAL_OFFER) {
            throw new InvalidStateException("cannot create an offer in state " + state);
        }
        var ice = iceForNext(options.iceRestart() || iceRestartRequested);
        var slots = planOffer();
        var assignments = new HashMap<String, RtpTransceiver>();
        for (var slot : slots) {
            if (slot.transceiver() != null && slot.transceiver().mid == null) {
                assignments.put(slot.mid(), slot.transceiver());
            }
        }
        var negotiatedBundle = negotiatedBundle();
        var offeredMids = slots.stream().filter(slot -> !slot.rejected()).map(Slot::mid).toList();
        var sections = new ArrayList<MediaDescription>();
        var firstOfKind = new HashSet<String>();
        String firstMid = null;
        for (var slot : slots) {
            if (slot.rejected()) {
                sections.add(rejectedSection(slot));
                continue;
            }
            var bundleOnly = isBundleOnly(slot, negotiatedBundle, firstMid, firstOfKind);
            if (firstMid == null) {
                firstMid = slot.mid();
            }
            firstOfKind.add(slot.kind());
            var port = bundleOnly ? 0 : 9;
            var tlsId = localTlsId(negotiatedBundle.contains(slot.mid()) ? negotiatedBundle.getFirst() : firstMid,
                    false);
            if (slot.data()) {
                sections.add(dataSection(slot.mid(), port, bundleOnly, ice, SetupRole.ACTPASS, tlsId));
            } else {
                sections.add(offerMediaSection(slot.transceiver(), slot.mid(), port, bundleOnly, ice, tlsId));
            }
        }
        var description = new SessionDescription(sessionLines(offeredMids, true), sections);
        var text = finish(description);
        lastCreatedOffer = text;
        lastOfferAssignments = Map.copyOf(assignments);
        return JsepDescription.offer(text);
    }

    /// Lays out the sections of the next offer: the existing ones in place, then new transceivers in recycled or
    /// appended sections, then the data section.
    private List<Slot> planOffer() {
        var base = pendingLocal != null ? pendingLocal : currentLocal;
        var slots = new ArrayList<Slot>();
        var usedMids = usedMids();
        var hasData = false;
        if (base != null) {
            for (var section : base.sdp().media()) {
                var mid = section.mid().orElse(null);
                if (section.media().equals("application")) {
                    var alive = dataRequested || !section.isRejected();
                    slots.add(new Slot("application", null, mid, !alive || mid == null, true, section));
                    hasData |= alive && mid != null;
                    continue;
                }
                var transceiver = mid == null ? null : transceiverByMid(mid);
                if (transceiver != null && !transceiver.stopped) {
                    slots.add(new Slot(section.media(), transceiver, mid, transceiver.stopping, false, section));
                } else {
                    slots.add(new Slot(section.media(), null, mid, true, false, section));
                }
            }
        }
        for (var transceiver : connection.transceiverList()) {
            if (transceiver.mid != null || transceiver.stopped || transceiver.stopping) {
                continue;
            }
            var mid = nextMid(usedMids);
            var slot = new Slot(kindName(transceiver.kind()), transceiver, mid, false, false, null);
            var recycled = recyclableIndex(slots);
            if (recycled >= 0) {
                slots.set(recycled, slot);
            } else {
                slots.add(slot);
            }
        }
        if (dataRequested && !hasData) {
            var mid = dataMid != null && !usedMidsExcludingData().contains(dataMid) ? dataMid : nextMid(usedMids);
            var slot = new Slot("application", null, mid, false, true, null);
            var recycled = recyclableIndex(slots);
            if (recycled >= 0) {
                slots.set(recycled, slot);
            } else {
                slots.add(slot);
            }
        }
        return slots;
    }

    /// {@return the index of the first dead section both current descriptions rejected, or `-1`}
    private int recyclableIndex(List<Slot> slots) {
        for (var index = 0; index < slots.size(); index++) {
            var slot = slots.get(index);
            if (slot.rejected() && slot.transceiver() == null && slot.previous() != null && rejectedInCurrent(index)) {
                return index;
            }
        }
        return -1;
    }

    /// {@return whether the section at `index` is rejected in both current descriptions}
    private boolean rejectedInCurrent(int index) {
        if (currentLocal == null || currentRemote == null) {
            return false;
        }
        var local = currentLocal.sdp().media();
        var remote = currentRemote.sdp().media();
        return index < local.size() && index < remote.size() && local.get(index).isRejected()
                && remote.get(index).isRejected();
    }

    /// {@return whether a section of the next offer is offered `bundle-only`}
    private boolean isBundleOnly(Slot slot, List<String> negotiatedBundle, String firstMid, Set<String> firstOfKind) {
        if (negotiatedBundle.contains(slot.mid()) || firstMid == null) {
            return false;
        }
        return switch (connection.configuration().bundlePolicy()) {
            case MAX_BUNDLE -> true;
            case BALANCED -> firstOfKind.contains(slot.kind()) || !negotiatedBundle.isEmpty();
            case MAX_COMPAT -> false;
        };
    }

    /// Writes the media section of a transceiver in an offer.
    private MediaDescription offerMediaSection(RtpTransceiver transceiver, String mid, int port, boolean bundleOnly,
                                               Negotiated.IceCredentials ice, String tlsId) {
        var codecs = offerCodecs(transceiver);
        var builder = new SectionBuilder(kindName(transceiver.kind()), port, RTP_PROTOCOL);
        formats(builder, codecs);
        builder.line(new SdpLine('c', "IN IP4 0.0.0.0"));
        receiveBitrateLine(builder, transceiver);
        builder.attribute(new SdpAttribute.Rtcp(9, Optional.of("IN IP4 0.0.0.0")));
        transportAttributes(builder, ice, SetupRole.ACTPASS, tlsId);
        builder.attribute(new SdpAttribute.Mid(mid));
        if (bundleOnly) {
            builder.attribute(new SdpAttribute.BundleOnly());
        }
        for (var extension : offerExtensions(transceiver)) {
            var direction = extension.direction() == TransceiverDirection.SENDRECV ? Optional.<MediaDirection>empty()
                    : Optional.of(toSdp(extension.direction()));
            builder.attribute(new SdpAttribute.Extmap(extensionId(extension.uri()), direction, extension.uri(),
                    Optional.empty()));
        }
        var direction = transceiver.direction;
        builder.attribute(new SdpAttribute.Direction(toSdp(direction)));
        var sender = transceiver.sender();
        if (direction.sends()) {
            msidLines(builder, sender);
        }
        builder.attribute(new SdpAttribute.RtcpMux());
        builder.attribute(new SdpAttribute.RtcpRsize());
        builder.attribute(new SdpAttribute.Cryptex());
        builder.attribute(new SdpAttribute.RtcpFb(OptionalInt.empty(), CodecCatalog.CCFB.type(),
                CodecCatalog.CCFB.parameter()));
        codecLines(builder, codecs);
        if (direction.sends()) {
            var layers = sender.layers();
            if (layers.size() > 1) {
                for (var layer : layers) {
                    builder.attribute(new SdpAttribute.Rid(layer.rid().orElseThrow(), SdpAttribute.Rid.Direction.SEND,
                            List.of(), Map.of()));
                }
                builder.attribute(SdpAttribute.Simulcast.sending(layers.stream()
                        .map(layer -> layer.rid().orElseThrow()).toList()));
            } else {
                ssrcLines(builder, sender, layers.getFirst(), hasRtx(codecs));
            }
        }
        return builder.build();
    }

    /// {@return the codecs a transceiver offers, with their payload types: media codecs with their RTX, then RED,
    /// FEC and telephone-event}
    private List<Negotiated.CodecEntry> offerCodecs(RtpTransceiver transceiver) {
        var available = transceiver.codecPreferences.isEmpty()
                ? CodecCatalog.ofKind(connection.configuration().codecs(), transceiver.kind())
                : transceiver.codecPreferences;
        var rtx = available.stream().filter(codec -> CodecCatalog.subtype(codec).equals(CodecCatalog.RTX)).findFirst();
        var result = new ArrayList<Negotiated.CodecEntry>();
        Negotiated.CodecEntry opus = null;
        for (var codec : available) {
            if (CodecCatalog.isAuxiliary(codec)) {
                continue;
            }
            var pt = payloadType(codec);
            var rtxPt = rtx.isPresent() && transceiver.kind() == MediaKind.VIDEO
                    && !CodecCatalog.subtype(codec).equals(CodecCatalog.TELEPHONE_EVENT)
                    ? OptionalInt.of(payloadType("rtx:" + CodecCatalog.key(codec), rtx.get()))
                    : OptionalInt.empty();
            var entry = new Negotiated.CodecEntry(pt, codec, CodecCatalog.feedback(codec), rtxPt);
            result.add(entry);
            if (CodecCatalog.subtype(codec).equals("opus") && opus == null) {
                opus = entry;
                var red = available.stream().filter(candidate -> CodecCatalog.subtype(candidate)
                        .equals(CodecCatalog.RED)).findFirst();
                if (red.isPresent()) {
                    var redCodec = withParameters(red.get(), Map.of(pt + "/" + pt, ""));
                    result.add(new Negotiated.CodecEntry(payloadType(red.get()), redCodec, List.of(),
                            OptionalInt.empty()));
                }
            }
        }
        if (transceiver.kind() == MediaKind.VIDEO) {
            for (var codec : available) {
                var subtype = CodecCatalog.subtype(codec);
                if (subtype.equals(CodecCatalog.RED) || subtype.equals(CodecCatalog.ULPFEC)
                        || subtype.equals(CodecCatalog.FLEXFEC)) {
                    var rtxPt = rtx.isPresent() && subtype.equals(CodecCatalog.RED)
                            ? OptionalInt.of(payloadType("rtx:" + CodecCatalog.key(codec), rtx.get()))
                            : OptionalInt.empty();
                    result.add(new Negotiated.CodecEntry(payloadType(codec), codec, List.of(), rtxPt));
                }
            }
        }
        return result;
    }

    /// {@return the header extensions a transceiver offers, with their directions: those of
    /// [RtpTransceiver#headerExtensionsToNegotiate()] that are not `STOPPED`}
    private static List<RtpHeaderExtensionCapability> offerExtensions(RtpTransceiver transceiver) {
        return transceiver.headerExtensions.stream()
                .filter(extension -> extension.direction() != TransceiverDirection.STOPPED).toList();
    }

    /// Appends the `b=TIAS` line of a transceiver's receive bitrate cap, when it has one.
    private static void receiveBitrateLine(SectionBuilder builder, RtpTransceiver transceiver) {
        transceiver.receiveBitrateCap.ifPresent(cap -> builder.line(new Bandwidth(Bandwidth.TIAS, cap).toLine()));
    }


    /// Writes an answer to the pending remote offer.
    ///
    /// @throws InvalidStateException if the signaling state is neither `HAVE_REMOTE_OFFER` nor
    ///                               `HAVE_LOCAL_PRANSWER`
    JsepDescription createAnswer() {
        if (state != SignalingState.HAVE_REMOTE_OFFER && state != SignalingState.HAVE_LOCAL_PRANSWER) {
            throw new InvalidStateException("cannot create an answer in state " + state);
        }
        var offer = pendingRemote.sdp();
        var ice = iceForNext(remoteRestartsIce(offer));
        var setup = answerSetup(offer);
        var offeredGroup = offer.bundleGroups().stream().findFirst().map(SdpAttribute.Group::mids).orElse(List.of());
        var sections = new ArrayList<MediaDescription>();
        var accepted = new ArrayList<String>();
        for (var remote : offer.media()) {
            var mid = remote.mid().orElse(null);
            if (remote.isRejected() || mid == null || !isSupported(remote)) {
                sections.add(rejectAnswer(remote));
                continue;
            }
            var tlsId = localTlsId(mid, remoteRestartsDtls(offer, remote));
            MediaDescription answer;
            if (remote.media().equals("application")) {
                answer = dataSection(mid, 9, false, ice, setup, tlsId);
            } else {
                var transceiver = transceiverByMid(mid);
                answer = transceiver == null || transceiver.stopping || transceiver.stopped
                        ? null : answerMediaSection(transceiver, offer, remote, ice, setup, tlsId);
            }
            if (answer == null) {
                sections.add(rejectAnswer(remote));
            } else {
                sections.add(answer);
                if (offeredGroup.contains(mid)) {
                    accepted.add(mid);
                }
            }
        }
        var ordered = offeredGroup.stream().filter(accepted::contains).toList();
        if (!ordered.isEmpty()) {
            var tagTlsId = localTlsId(ordered.getFirst(), false);
            sections.replaceAll(section -> section.mid().filter(ordered::contains).isPresent()
                    ? withTlsId(section, tagTlsId) : section);
        }
        var lines = sessionLines(ordered, offer.attribute(SdpAttribute.ExtmapAllowMixed.class).isPresent());
        var text = finish(new SessionDescription(lines, sections));
        lastCreatedAnswer = text;
        return JsepDescription.answer(text);
    }

    /// {@return the setup role of an answer: the established DTLS role, else `active` unless the offerer insists on
    /// it}
    private SetupRole answerSetup(SessionDescription offer) {
        if (dtlsRole != null) {
            return dtlsRole == DtlsRole.CLIENT ? SetupRole.ACTIVE : SetupRole.PASSIVE;
        }
        for (var section : offer.media()) {
            if (section.isRejected()) {
                continue;
            }
            var setup = offer.attribute(section, SdpAttribute.Setup.class).map(SdpAttribute.Setup::role)
                    .orElse(SetupRole.ACTIVE);
            return setup == SetupRole.ACTIVE ? SetupRole.PASSIVE : SetupRole.ACTIVE;
        }
        return SetupRole.ACTIVE;
    }

    /// {@return a section whose `a=tls-id` line carries `tlsId`, in place}
    private static MediaDescription withTlsId(MediaDescription section, String tlsId) {
        var line = new SdpAttribute.TlsId(tlsId).toLine();
        return section.withLines(section.lines().stream()
                .map(candidate -> candidate.isAttribute("tls-id") ? line : candidate).toList());
    }

    /// Writes the answer section of a transceiver, or returns `null` to reject the offered section.
    private MediaDescription answerMediaSection(RtpTransceiver transceiver, SessionDescription offer,
                                                MediaDescription remote, Negotiated.IceCredentials ice,
                                                SetupRole setup, String tlsId) {
        var codecs = answerCodecs(transceiver, remote);
        if (codecs.stream().noneMatch(entry -> !CodecCatalog.isAuxiliary(entry.codec())
                && !CodecCatalog.subtype(entry.codec()).equals(CodecCatalog.TELEPHONE_EVENT))) {
            return null;
        }
        var mid = remote.mid().orElseThrow();
        var remoteDirection = offer.direction(remote);
        var direction = TransceiverDirection.of(transceiver.direction.sends() && remoteDirection.receives(),
                transceiver.direction.receives() && remoteDirection.sends());
        var builder = new SectionBuilder(remote.media(), 9, remote.protocol());
        formats(builder, codecs);
        builder.line(new SdpLine('c', "IN IP4 0.0.0.0"));
        receiveBitrateLine(builder, transceiver);
        builder.attribute(new SdpAttribute.Rtcp(9, Optional.of("IN IP4 0.0.0.0")));
        transportAttributes(builder, ice, setup, tlsId);
        builder.attribute(new SdpAttribute.Mid(mid));
        for (var extmap : remote.attributes(SdpAttribute.Extmap.class)) {
            var local = answerExtensionDirection(transceiver, extmap);
            if (local.isPresent()) {
                extensionIds.putIfAbsent(extmap.uri(), extmap.id());
                var written = local.get() == MediaDirection.SENDRECV ? Optional.<MediaDirection>empty() : local;
                builder.attribute(new SdpAttribute.Extmap(extmap.id(), written, extmap.uri(), Optional.empty()));
            }
        }
        builder.attribute(new SdpAttribute.Direction(toSdp(direction)));
        var sender = transceiver.sender();
        if (direction.sends()) {
            msidLines(builder, sender);
        }
        builder.attribute(new SdpAttribute.RtcpMux());
        if (remote.hasAttribute("rtcp-rsize")) {
            builder.attribute(new SdpAttribute.RtcpRsize());
        }
        if (hasCryptex(offer, remote)) {
            builder.attribute(new SdpAttribute.Cryptex());
        }
        if (hasCongestionControlFeedback(remote)) {
            builder.attribute(new SdpAttribute.RtcpFb(OptionalInt.empty(), CodecCatalog.CCFB.type(),
                    CodecCatalog.CCFB.parameter()));
        }
        codecLines(builder, codecs);
        var remoteSimulcast = remote.attribute(SdpAttribute.Simulcast.class);
        var remoteRids = remote.attributes(SdpAttribute.Rid.class);
        if (direction.receives() && remoteSimulcast.isPresent() && !remoteSimulcast.get().send().isEmpty()) {
            var receiveStreams = remoteSimulcast.get().send();
            var declared = new HashSet<String>();
            for (var rid : remoteRids) {
                if (rid.direction() == SdpAttribute.Rid.Direction.SEND) {
                    builder.attribute(new SdpAttribute.Rid(rid.id(), SdpAttribute.Rid.Direction.RECV,
                            rid.payloadTypes(), rid.restrictions()));
                    declared.add(rid.id());
                }
            }
            var kept = receiveStreams.stream()
                    .map(alternatives -> alternatives.stream().filter(stream -> declared.contains(stream.rid()))
                            .toList())
                    .filter(alternatives -> !alternatives.isEmpty()).toList();
            if (!kept.isEmpty()) {
                builder.attribute(new SdpAttribute.Simulcast(List.of(), kept));
            }
        }
        if (direction.sends()) {
            var layers = sender.layers();
            var offeredReceive = remoteSimulcast.map(SdpAttribute.Simulcast::receive).orElse(List.of());
            if (layers.size() > 1 && !offeredReceive.isEmpty()) {
                var wanted = new LinkedHashSet<String>();
                offeredReceive.forEach(alternatives -> alternatives.forEach(stream -> wanted.add(stream.rid())));
                var sent = layers.stream().map(layer -> layer.rid().orElseThrow()).filter(wanted::contains).toList();
                for (var rid : sent) {
                    builder.attribute(new SdpAttribute.Rid(rid, SdpAttribute.Rid.Direction.SEND, List.of(),
                            Map.of()));
                }
                if (!sent.isEmpty()) {
                    builder.attribute(SdpAttribute.Simulcast.sending(sent));
                }
            } else {
                ssrcLines(builder, sender, layers.getFirst(), hasRtx(codecs));
            }
        }
        return builder.build();
    }

    /// {@return the codecs an answer accepts from an offered section, with the offer's payload types}
    private List<Negotiated.CodecEntry> answerCodecs(RtpTransceiver transceiver, MediaDescription remote) {
        var local = transceiver.codecPreferences.isEmpty()
                ? CodecCatalog.ofKind(connection.configuration().codecs(), transceiver.kind())
                : transceiver.codecPreferences;
        var offered = remoteCodecs(remote);
        var media = new ArrayList<Negotiated.CodecEntry>();
        var mediaOrder = new ArrayList<Negotiated.CodecEntry>();
        for (var entry : offered) {
            if (CodecCatalog.isAuxiliary(entry.codec())) {
                continue;
            }
            var match = local.stream().filter(codec -> CodecCatalog.matches(codec, entry.codec())).findFirst();
            if (match.isEmpty()) {
                continue;
            }
            var feedback = entry.feedback().stream()
                    .filter(fb -> CodecCatalog.feedback(match.get()).contains(fb)).toList();
            media.add(new Negotiated.CodecEntry(entry.payloadType(), entry.codec(), feedback, OptionalInt.empty()));
            adoptPayloadType(entry.codec(), entry.payloadType());
        }
        if (!transceiver.codecPreferences.isEmpty()) {
            for (var preferred : transceiver.codecPreferences) {
                for (var entry : media) {
                    if (CodecCatalog.matches(preferred, entry.codec()) && !mediaOrder.contains(entry)) {
                        mediaOrder.add(entry);
                    }
                }
            }
        } else {
            mediaOrder.addAll(media);
        }
        var localRtx = local.stream().anyMatch(codec -> CodecCatalog.subtype(codec).equals(CodecCatalog.RTX));
        var result = new ArrayList<Negotiated.CodecEntry>();
        var included = new HashSet<Integer>();
        for (var entry : mediaOrder) {
            var rtx = localRtx ? rtxFor(offered, entry.payloadType()) : OptionalInt.empty();
            result.add(new Negotiated.CodecEntry(entry.payloadType(), entry.codec(), entry.feedback(), rtx));
            included.add(entry.payloadType());
        }
        for (var entry : offered) {
            var subtype = CodecCatalog.subtype(entry.codec());
            var supported = local.stream().anyMatch(codec -> CodecCatalog.subtype(codec).equals(subtype));
            if (!supported) {
                continue;
            }
            if (subtype.equals(CodecCatalog.RED) && transceiver.kind() == MediaKind.AUDIO) {
                var primary = redPrimary(entry.codec());
                if (primary.isPresent() && included.contains(primary.getAsInt())) {
                    result.add(entry);
                }
            } else if (transceiver.kind() == MediaKind.VIDEO && (subtype.equals(CodecCatalog.RED)
                    || subtype.equals(CodecCatalog.ULPFEC) || subtype.equals(CodecCatalog.FLEXFEC))) {
                var rtx = subtype.equals(CodecCatalog.RED) && localRtx ? rtxFor(offered, entry.payloadType())
                        : OptionalInt.empty();
                result.add(new Negotiated.CodecEntry(entry.payloadType(), entry.codec(), List.of(), rtx));
            }
        }
        return result;
    }

    /// {@return the payload type of the RTX format whose `apt` is `payloadType`, if offered}
    private static OptionalInt rtxFor(List<Negotiated.CodecEntry> offered, int payloadType) {
        for (var entry : offered) {
            if (CodecCatalog.subtype(entry.codec()).equals(CodecCatalog.RTX)
                    && CodecCatalog.parameter(entry.codec(), "apt").equals(Optional.of(Integer.toString(payloadType)))) {
                return OptionalInt.of(entry.payloadType());
            }
        }
        return OptionalInt.empty();
    }

    /// {@return the primary payload type an audio RED format's `a=fmtp` names, such as `111` in `111/111`}
    private static OptionalInt redPrimary(Codec red) {
        for (var key : red.formatParameters().keySet()) {
            var slash = key.indexOf('/');
            try {
                return OptionalInt.of(Integer.parseInt(slash < 0 ? key : key.substring(0, slash)));
            } catch (NumberFormatException exception) {
                return OptionalInt.empty();
            }
        }
        return OptionalInt.empty();
    }

    /// {@return the direction, from this side's point of view, an answer accepts an offered header extension in: the
    /// transceiver's direction for it intersected with the reverse of the offered one, or an empty optional when the
    /// transceiver does not negotiate it}
    private static Optional<MediaDirection> answerExtensionDirection(RtpTransceiver transceiver,
                                                                     SdpAttribute.Extmap extmap) {
        for (var extension : transceiver.headerExtensions) {
            if (extension.uri().equals(extmap.uri())) {
                if (extension.direction() == TransceiverDirection.STOPPED) {
                    return Optional.empty();
                }
                var offered = extmap.direction().orElse(MediaDirection.SENDRECV).reverse();
                return Optional.of(toSdp(extension.direction()).intersect(offered));
            }
        }
        return Optional.empty();
    }

    /// {@return whether a section, or the session level of its description, carries `a=cryptex`}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc9335.html RFC 9335: Completely Encrypting RTP Header Extensions and Contributing Sources
    static boolean hasCryptex(SessionDescription description, MediaDescription section) {
        return description.attribute(section, SdpAttribute.Cryptex.class).isPresent();
    }

    /// {@return whether a section carries `a=rtcp-fb:* ack ccfb`}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8888.html RFC 8888: RTP Control Protocol (RTCP) Feedback for Congestion Control
    static boolean hasCongestionControlFeedback(MediaDescription section) {
        return section.attributes(SdpAttribute.RtcpFb.class).stream()
                .anyMatch(feedback -> feedback.payloadType().isEmpty() && isCongestionControlFeedback(feedback));
    }

    /// {@return whether a feedback attribute is the `ack ccfb` mechanism, whatever its payload type}
    private static boolean isCongestionControlFeedback(SdpAttribute.RtcpFb feedback) {
        return feedback.type().equals(CodecCatalog.CCFB.type()) && feedback.parameter().equals(CodecCatalog.CCFB.parameter());
    }

    /// {@return a rejected answer section: port `0`, the offered media type, protocol and formats}
    private static MediaDescription rejectAnswer(MediaDescription remote) {
        var builder = new SectionBuilder(remote.media(), 0, remote.protocol()).formats(remote.formats());
        builder.line(new SdpLine('c', "IN IP4 0.0.0.0"));
        remote.mid().ifPresent(mid -> builder.attribute(new SdpAttribute.Mid(mid)));
        return builder.build();
    }

    /// {@return a rejected offer section for a stopped transceiver or a dead section}
    private MediaDescription rejectedSection(Slot slot) {
        var previous = slot.previous();
        var media = previous != null ? previous.media() : slot.kind();
        var protocol = previous != null ? previous.protocol() : slot.data() ? SCTP_PROTOCOL : RTP_PROTOCOL;
        var formats = previous != null ? previous.formats() : List.<String>of();
        if (formats.isEmpty()) {
            formats = slot.data() ? List.of("webrtc-datachannel") : List.of("0");
        }
        var builder = new SectionBuilder(media, 0, protocol).formats(formats);
        builder.line(new SdpLine('c', "IN IP4 0.0.0.0"));
        if (slot.mid() != null) {
            builder.attribute(new SdpAttribute.Mid(slot.mid()));
        }
        if (!slot.data()) {
            builder.attribute(new SdpAttribute.Direction(MediaDirection.INACTIVE));
        }
        return builder.build();
    }

    /// Writes the data section.
    private MediaDescription dataSection(String mid, int port, boolean bundleOnly, Negotiated.IceCredentials ice,
                                         SetupRole setup, String tlsId) {
        var builder = new SectionBuilder("application", port, SCTP_PROTOCOL).format("webrtc-datachannel");
        builder.line(new SdpLine('c', "IN IP4 0.0.0.0"));
        transportAttributes(builder, ice, setup, tlsId);
        builder.attribute(new SdpAttribute.Mid(mid));
        if (bundleOnly) {
            builder.attribute(new SdpAttribute.BundleOnly());
        }
        builder.attribute(new SdpAttribute.SctpPort(SCTP_PORT));
        builder.attribute(new SdpAttribute.MaxMessageSize(MAX_MESSAGE_SIZE));
        return builder.build();
    }


    /// {@return the session-level lines: version, origin placeholder, name, timing, BUNDLE, mixed extensions,
    /// ICE-lite}
    private List<SdpLine> sessionLines(List<String> bundleMids, boolean allowMixed) {
        var lines = new ArrayList<SdpLine>();
        lines.add(new SdpLine('v', "0"));
        lines.add(new Origin("-", sessionId, sessionVersion, "IN", "IP4", "127.0.0.1").toLine());
        lines.add(new SdpLine('s', "-"));
        lines.add(new SdpLine('t', "0 0"));
        if (connection.configuration().iceLite()) {
            lines.add(new SdpAttribute.IceLite().toLine());
        }
        if (!bundleMids.isEmpty()) {
            lines.add(new SdpAttribute.Group(SdpAttribute.Group.BUNDLE, bundleMids).toLine());
        }
        if (allowMixed) {
            lines.add(new SdpAttribute.ExtmapAllowMixed().toLine());
        }
        lines.add(SdpLine.attribute("msid-semantic", " WMS"));
        return lines;
    }

    /// Fixes the session version of a created description: unchanged when only the version would differ from the
    /// last created one, incremented otherwise.
    private String finish(SessionDescription description) {
        var body = description.withLines(description.lines().stream()
                .filter(line -> line.type() != 'o').toList()).encode();
        if (lastCreatedBody != null && !body.equals(lastCreatedBody)) {
            sessionVersion++;
        }
        lastCreatedBody = body;
        var lines = description.lines().stream()
                .map(line -> line.type() == 'o'
                        ? new Origin("-", sessionId, sessionVersion, "IN", "IP4", "127.0.0.1").toLine() : line)
                .toList();
        return description.withLines(lines).encode();
    }

    /// Appends the ICE and DTLS attributes of a section.
    private void transportAttributes(SectionBuilder builder, Negotiated.IceCredentials ice, SetupRole setup,
                                     String tlsId) {
        builder.attribute(new SdpAttribute.IceUfrag(ice.usernameFragment()));
        builder.attribute(new SdpAttribute.IcePwd(ice.password()));
        builder.attribute(new SdpAttribute.IceOptions(List.of("trickle")));
        for (var fingerprint : connection.backend().fingerprints()) {
            builder.attribute(fingerprint);
        }
        builder.attribute(new SdpAttribute.Setup(setup));
        builder.attribute(new SdpAttribute.TlsId(tlsId));
    }

    /// {@return the `a=tls-id` of a local transport: the one the latest applied local description wrote for it,
    /// unless `restart` asks for a new one or there is none; repeated calls return the same new value until a local
    /// description applies it}
    ///
    /// @param transportId the identification tag of the section that carries the transport
    /// @param restart     whether the transport's DTLS association restarts, which needs a new value (RFC 8842
    ///                    section 5)
    private String localTlsId(String transportId, boolean restart) {
        var fresh = freshTlsIds.get(transportId);
        if (fresh != null) {
            return fresh;
        }
        if (!restart) {
            var base = pendingLocal != null ? pendingLocal : currentLocal;
            if (base != null) {
                var applied = base.sdp().mediaByMid(transportId)
                        .flatMap(section -> base.sdp().attribute(section, SdpAttribute.TlsId.class));
                if (applied.isPresent()) {
                    return applied.get().id();
                }
            }
        }
        var created = randomToken(TLS_ID_LENGTH);
        freshTlsIds.put(transportId, created);
        return created;
    }

    /// {@return whether a remote offer asks for a new DTLS association on the transport a section ran in the
    /// current remote description: its `a=tls-id` or its set of fingerprints changed}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8842.html RFC 8842: Session Description Protocol (SDP) Offer/Answer Considerations for Datagram Transport Layer Security (DTLS) and Transport Layer Security (TLS)
    private boolean remoteRestartsDtls(SessionDescription offer, MediaDescription section) {
        if (currentRemote == null) {
            return false;
        }
        var mid = section.mid().orElse(null);
        var previous = mid == null ? Optional.<MediaDescription>empty() : currentRemote.sdp().mediaByMid(mid);
        if (previous.isEmpty() || previous.get().isRejected()) {
            return false;
        }
        var oldTlsId = currentRemote.sdp().attribute(previous.get(), SdpAttribute.TlsId.class);
        var newTlsId = offer.attribute(section, SdpAttribute.TlsId.class);
        if (oldTlsId.isPresent() && newTlsId.isPresent() && !oldTlsId.equals(newTlsId)) {
            return true;
        }
        return !fingerprintSet(currentRemote.sdp(), previous.get()).equals(fingerprintSet(offer, section));
    }

    /// {@return the fingerprints of a section, else of its session level, as a set}
    private static Set<SdpAttribute.Fingerprint> fingerprintSet(SessionDescription description,
                                                                MediaDescription section) {
        var fingerprints = section.attributes(SdpAttribute.Fingerprint.class);
        return new HashSet<>(fingerprints.isEmpty() ? description.attributes(SdpAttribute.Fingerprint.class)
                : fingerprints);
    }

    /// Appends the `a=msid` lines of a sender: one per stream, or one with stream id `-` without streams.
    private static void msidLines(SectionBuilder builder, RtpSender sender) {
        var streams = sender.streams();
        if (streams.isEmpty()) {
            builder.attribute(new SdpAttribute.Msid("-", Optional.of(sender.msidTrackId())));
        } else {
            for (var stream : streams) {
                builder.attribute(new SdpAttribute.Msid(stream, Optional.of(sender.msidTrackId())));
            }
        }
    }

    /// Appends the `a=ssrc-group` and `a=ssrc` lines of a sender without simulcast.
    private void ssrcLines(SectionBuilder builder, RtpSender sender, Negotiated.SendLayer layer, boolean rtx) {
        var msid = (sender.streams().isEmpty() ? "-" : sender.streams().getFirst()) + " " + sender.msidTrackId();
        if (rtx && layer.rtxSsrc().isPresent()) {
            builder.attribute(new SdpAttribute.SsrcGroup(SdpAttribute.SsrcGroup.FID,
                    List.of(layer.ssrc(), layer.rtxSsrc().getAsLong())));
        }
        builder.attribute(new SdpAttribute.Ssrc(layer.ssrc(), "cname", Optional.of(cname)));
        builder.attribute(new SdpAttribute.Ssrc(layer.ssrc(), "msid", Optional.of(msid)));
        if (rtx && layer.rtxSsrc().isPresent()) {
            builder.attribute(new SdpAttribute.Ssrc(layer.rtxSsrc().getAsLong(), "cname", Optional.of(cname)));
            builder.attribute(new SdpAttribute.Ssrc(layer.rtxSsrc().getAsLong(), "msid", Optional.of(msid)));
        }
    }

    /// Appends the payload types of the codecs to the `m=` line, each followed by that of its RTX format.
    private static void formats(SectionBuilder builder, List<Negotiated.CodecEntry> codecs) {
        for (var entry : codecs) {
            builder.format(Integer.toString(entry.payloadType()));
            entry.rtxPayloadType().ifPresent(rtx -> builder.format(Integer.toString(rtx)));
        }
    }

    /// {@return whether any codec has an RTX format}
    private static boolean hasRtx(List<Negotiated.CodecEntry> codecs) {
        return codecs.stream().anyMatch(entry -> entry.rtxPayloadType().isPresent());
    }

    /// Appends `a=rtpmap`, `a=rtcp-fb` and `a=fmtp` for every codec and its RTX format.
    private static void codecLines(SectionBuilder builder, List<Negotiated.CodecEntry> codecs) {
        var rtxLines = new ArrayList<Runnable>();
        for (var entry : codecs) {
            var codec = entry.codec();
            var channels = CodecCatalog.kindOf(codec) == MediaKind.AUDIO && CodecCatalog.channels(codec) > 1
                    ? OptionalInt.of(CodecCatalog.channels(codec)) : OptionalInt.empty();
            builder.attribute(new SdpAttribute.Rtpmap(entry.payloadType(), encodingName(codec), codec.clockRate(),
                    channels));
            for (var feedback : entry.feedback()) {
                builder.attribute(new SdpAttribute.RtcpFb(OptionalInt.of(entry.payloadType()), feedback.type(),
                        feedback.parameter()));
            }
            CodecCatalog.fmtpLine(codec).or(() -> CodecCatalog.subtype(codec).equals(CodecCatalog.TELEPHONE_EVENT)
                            ? Optional.of("0-15") : Optional.empty())
                    .ifPresent(fmtp -> builder.attribute(new SdpAttribute.Fmtp(entry.payloadType(), fmtp)));
            if (entry.rtxPayloadType().isPresent()) {
                var rtxPt = entry.rtxPayloadType().getAsInt();
                builder.attribute(new SdpAttribute.Rtpmap(rtxPt, "rtx", codec.clockRate(), OptionalInt.empty()));
                builder.attribute(new SdpAttribute.Fmtp(rtxPt, "apt=" + entry.payloadType()));
            }
        }
        rtxLines.forEach(Runnable::run);
    }

    /// {@return the encoding name an `a=rtpmap` line writes for a codec: the media subtype as the codec spells it}
    private static String encodingName(Codec codec) {
        return codec.mimeType().substring(codec.mimeType().indexOf('/') + 1);
    }

    /// {@return a copy of `codec` with other format parameters}
    private static Codec withParameters(Codec codec, Map<String, String> parameters) {
        return new Codec(codec.mimeType(), codec.clockRate(), codec.channels(), parameters);
    }


    /// Applies a local description, the JSEP `setLocalDescription`.
    ///
    /// @return the negotiation the description completes, or an empty optional for an offer
    Optional<Negotiated> setLocalDescription(JsepDescription description) {
        if (description.type() == JsepType.ROLLBACK) {
            if (state != SignalingState.HAVE_LOCAL_OFFER) {
                throw new InvalidStateException("no local offer to roll back in state " + state);
            }
            rollback();
            return Optional.empty();
        }
        var text = description.sdp().isBlank()
                ? description.type() == JsepType.OFFER ? lastCreatedOffer : lastCreatedAnswer
                : description.sdp();
        if (text == null) {
            text = description.type() == JsepType.OFFER ? createOffer(OfferOptions.DEFAULT).sdp()
                    : createAnswer().sdp();
        }
        var type = description.type();
        switch (type) {
            case OFFER -> {
                if (state != SignalingState.STABLE && state != SignalingState.HAVE_LOCAL_OFFER) {
                    throw new InvalidStateException("cannot apply a local offer in state " + state);
                }
            }
            case ANSWER, PRANSWER -> {
                if (state != SignalingState.HAVE_REMOTE_OFFER && state != SignalingState.HAVE_LOCAL_PRANSWER) {
                    throw new InvalidStateException("cannot apply a local answer in state " + state);
                }
            }
            case ROLLBACK -> throw new AssertionError();
        }
        var created = type == JsepType.OFFER ? lastCreatedOffer : lastCreatedAnswer;
        if (created == null) {
            throw new InvalidModificationException("no " + type.value() + " was created to apply");
        }
        var parsed = parse(text);
        if (!text.equals(created)) {
            SdpMungingRules.check(parse(created), parsed);
        }
        var allRejected = parsed.media().stream().allMatch(MediaDescription::isRejected);
        var fallback = localIce != null ? localIce : nextIce;
        var credentials = iceCredentials(parsed).or(() -> allRejected ? Optional.ofNullable(fallback)
                : Optional.empty()).orElseThrow(
                () -> new InvalidModificationException("the description carries no ICE credentials"));
        if (type == JsepType.OFFER) {
            if (state == SignalingState.STABLE) {
                stable = snapshot();
            }
            for (var index = 0; index < parsed.media().size(); index++) {
                var section = parsed.media().get(index);
                var mid = section.mid().orElse(null);
                if (mid == null) {
                    continue;
                }
                if (section.media().equals("application")) {
                    dataMid = mid;
                    continue;
                }
                var transceiver = lastOfferAssignments.get(mid);
                if (transceiver != null && transceiver.mid == null) {
                    transceiver.mid = mid;
                    transceiver.mLineIndex = index;
                }
            }
            var restart = localIce != null && !localIce.equals(credentials);
            localIce = credentials;
            iceRestartRequested = false;
            freshTlsIds.clear();
            pendingLocal = new Description(JsepType.OFFER, parsed);
            localTransportOf = proposeLocalTransports(parsed);
            setState(SignalingState.HAVE_LOCAL_OFFER);
            startGathering(restart);
            return Optional.empty();
        }
        var restart = localIce != null && !localIce.equals(credentials);
        localIce = credentials;
        freshTlsIds.clear();
        var offer = pendingRemote.sdp();
        if (type == JsepType.PRANSWER) {
            pendingLocal = new Description(JsepType.PRANSWER, parsed);
            var result = negotiate(offer, parsed, false);
            startGathering(restart);
            setState(SignalingState.HAVE_LOCAL_PRANSWER);
            return Optional.of(result);
        }
        currentLocal = new Description(JsepType.ANSWER, parsed);
        currentRemote = pendingRemote;
        pendingLocal = null;
        pendingRemote = null;
        var result = negotiate(offer, parsed, false);
        startGathering(restart);
        finishNegotiation(result);
        setState(SignalingState.STABLE);
        return Optional.of(result);
    }

    /// Applies a remote description, the JSEP `setRemoteDescription`.
    ///
    /// @return the negotiation the description completes, or an empty optional for an offer
    Optional<Negotiated> setRemoteDescription(JsepDescription description) {
        if (description.type() == JsepType.ROLLBACK) {
            if (state != SignalingState.HAVE_REMOTE_OFFER) {
                throw new InvalidStateException("no remote offer to roll back in state " + state);
            }
            rollback();
            return Optional.empty();
        }
        var parsed = parse(description.sdp());
        var type = description.type();
        if (type == JsepType.OFFER && state == SignalingState.HAVE_LOCAL_OFFER) {
            rollback();
        }
        switch (type) {
            case OFFER -> {
                if (state != SignalingState.STABLE && state != SignalingState.HAVE_REMOTE_OFFER) {
                    throw new InvalidStateException("cannot apply a remote offer in state " + state);
                }
            }
            case ANSWER, PRANSWER -> {
                if (state != SignalingState.HAVE_LOCAL_OFFER && state != SignalingState.HAVE_REMOTE_PRANSWER) {
                    throw new InvalidStateException("cannot apply a remote answer in state " + state);
                }
            }
            case ROLLBACK -> throw new AssertionError();
        }
        RemoteDescriptionValidator.validate(parsed, type, type == JsepType.OFFER ? null : pendingLocal.sdp());
        if (type == JsepType.OFFER) {
            if (state == SignalingState.STABLE) {
                stable = snapshot();
            }
            associateRemoteOffer(parsed);
            pendingRemote = new Description(JsepType.OFFER, parsed);
            setState(SignalingState.HAVE_REMOTE_OFFER);
            processRemoteTracks(parsed);
            return Optional.empty();
        }
        var offer = pendingLocal.sdp();
        processRemoteTracks(parsed);
        if (type == JsepType.PRANSWER) {
            pendingRemote = new Description(JsepType.PRANSWER, parsed);
            var result = negotiate(offer, parsed, true);
            setState(SignalingState.HAVE_REMOTE_PRANSWER);
            return Optional.of(result);
        }
        currentRemote = new Description(JsepType.ANSWER, parsed);
        currentLocal = pendingLocal;
        pendingLocal = null;
        pendingRemote = null;
        var result = negotiate(offer, parsed, true);
        finishNegotiation(result);
        setState(SignalingState.STABLE);
        return Optional.of(result);
    }

    /// Binds the sections of a remote offer to transceivers, creating one for each section no transceiver takes.
    private void associateRemoteOffer(SessionDescription offer) {
        for (var index = 0; index < offer.media().size(); index++) {
            var section = offer.media().get(index);
            var mid = section.mid().orElse(null);
            if (mid == null) {
                continue;
            }
            if (section.media().equals("application")) {
                if (!section.isRejected()) {
                    dataMid = mid;
                }
                continue;
            }
            var kind = kindOf(section.media());
            if (kind.isEmpty() || !isDtlsSrtp(section.protocol())) {
                continue;
            }
            var transceiver = transceiverByMid(mid);
            if (transceiver == null && !section.isRejected()) {
                for (var candidate : connection.transceiverList()) {
                    if (candidate.mid == null && candidate.kind() == kind.get() && !candidate.stopped
                            && !candidate.stopping && candidate.usedByAddTrack && !candidate.createdByRemote) {
                        transceiver = candidate;
                        break;
                    }
                }
                if (transceiver == null) {
                    transceiver = connection.createRemoteTransceiver(kind.get());
                }
            }
            if (transceiver != null && transceiver.mid == null) {
                transceiver.mid = mid;
                transceiver.mLineIndex = index;
            }
        }
    }

    /// Announces the tracks a remote description starts sending and mutes those it stops, the W3C process of
    /// remote track addition and removal.
    private void processRemoteTracks(SessionDescription remote) {
        for (var section : remote.media()) {
            var mid = section.mid().orElse(null);
            if (mid == null || section.media().equals("application")) {
                continue;
            }
            var transceiver = transceiverByMid(mid);
            if (transceiver == null) {
                continue;
            }
            var sends = !section.isRejected() && remote.direction(section).sends();
            if (sends && !transceiver.receiving) {
                transceiver.receiving = true;
                var streams = section.attributes(SdpAttribute.Msid.class).stream()
                        .map(SdpAttribute.Msid::streamId).filter(stream -> !stream.equals("-")).distinct().toList();
                connection.announceTrack(transceiver, streams);
            } else if (!sends && transceiver.receiving) {
                transceiver.receiving = false;
                transceiver.receiver().track().mute();
            }
        }
    }

    /// Updates the transceivers after a final answer: current directions, stopped transceivers, data section.
    private void finishNegotiation(Negotiated result) {
        negotiated = result;
        stable = null;
        var answer = currentLocal.type() == JsepType.ANSWER ? currentLocal.sdp() : currentRemote.sdp();
        var weAnswered = currentLocal.type() == JsepType.ANSWER;
        var removed = new ArrayList<RtpTransceiver>();
        for (var transceiver : connection.transceiverList()) {
            if (transceiver.mid == null) {
                continue;
            }
            var section = answer.mediaByMid(transceiver.mid);
            if (section.isEmpty() || section.get().isRejected()) {
                if (transceiver.stopping || section.isPresent()) {
                    transceiver.stopped = true;
                    transceiver.stopping = false;
                    transceiver.currentDirection = null;
                    transceiver.sender().stopSending();
                    transceiver.receiver().track().end();
                    removed.add(transceiver);
                }
                continue;
            }
            var direction = answer.direction(section.get());
            var local = weAnswered ? direction : direction.reverse();
            transceiver.currentDirection = TransceiverDirection.of(local.sends(), local.receives());
            for (var media : result.media()) {
                if (media.transceiver() == transceiver) {
                    transceiver.negotiated = media;
                }
            }
        }
        for (var transceiver : removed) {
            connection.removeTransceiver(transceiver);
        }
        if (result.data().isEmpty()) {
            var dataSection = answer.media().stream().filter(section -> section.media().equals("application"))
                    .findFirst();
            if (dataSection.isPresent() && dataSection.get().isRejected()) {
                dataMid = null;
            }
        }
    }

    /// Restores the state captured when the connection last left `STABLE`.
    private void rollback() {
        var snapshot = stable;
        if (snapshot != null) {
            for (var transceiver : List.copyOf(connection.transceiverList())) {
                var fields = snapshot.fields().get(transceiver);
                if (fields == null) {
                    if (transceiver.usedByAddTrack) {
                        transceiver.mid = null;
                        transceiver.mLineIndex = -1;
                        transceiver.createdByRemote = false;
                        if (transceiver.receiving) {
                            transceiver.receiving = false;
                            transceiver.receiver().track().mute();
                        }
                    } else {
                        connection.removeTransceiver(transceiver);
                        transceiver.receiver().track().end();
                    }
                    continue;
                }
                transceiver.mid = (String) fields[0];
                transceiver.mLineIndex = (int) fields[1];
                var wasReceiving = (boolean) fields[2];
                if (transceiver.receiving && !wasReceiving) {
                    transceiver.receiver().track().mute();
                }
                transceiver.receiving = wasReceiving;
            }
            dataMid = snapshot.dataMid();
            localIce = snapshot.localIce();
            payloadTypes = new HashMap<>(snapshot.payloadTypes());
            extensionIds = new HashMap<>(snapshot.extensionIds());
            localTransportOf = new HashMap<>(snapshot.localTransportOf());
        }
        pendingLocal = null;
        pendingRemote = null;
        stable = null;
        setState(SignalingState.STABLE);
    }

    /// {@return what a rollback restores now}
    private Snapshot snapshot() {
        var fields = new IdentityHashMap<RtpTransceiver, Object[]>();
        for (var transceiver : connection.transceiverList()) {
            fields.put(transceiver, new Object[]{transceiver.mid, transceiver.mLineIndex, transceiver.receiving});
        }
        return new Snapshot(List.copyOf(connection.transceiverList()), fields, dataMid, localIce,
                Map.copyOf(payloadTypes), Map.copyOf(extensionIds), Map.copyOf(localTransportOf));
    }

    /// Changes the signaling state and raises the event.
    private void setState(SignalingState newState) {
        if (state != newState) {
            state = newState;
            connection.signalingStateChanged(newState);
        }
    }

    /// {@return the transport each section of a local offer gathers on: the negotiated BUNDLE transport, the first
    /// section of the offered group for a `bundle-only` section, or its own}
    private Map<String, String> proposeLocalTransports(SessionDescription offer) {
        var result = new HashMap<String, String>();
        var bundle = negotiatedBundle();
        var group = offer.bundleGroups().stream().findFirst().map(SdpAttribute.Group::mids).orElse(List.of());
        String tag = null;
        for (var section : offer.media()) {
            var mid = section.mid().orElse(null);
            if (mid == null) {
                continue;
            }
            if (!bundle.isEmpty() && bundle.contains(mid)) {
                result.put(mid, bundle.getFirst());
            } else if (section.port() == 0 && section.hasAttribute("bundle-only") && tag != null) {
                result.put(mid, tag);
            } else if (!section.isRejected()) {
                result.put(mid, mid);
            }
            if (tag == null && group.contains(mid) && !section.isRejected()) {
                tag = bundle.isEmpty() ? mid : bundle.getFirst();
            }
        }
        return result;
    }

    /// Starts gathering on every local transport not yet gathering, and on every transport after an ICE restart.
    private void startGathering(boolean restart) {
        for (var transport : new LinkedHashSet<>(localTransportOf.values())) {
            var current = gathering.get(transport);
            if (current == null || restart || !current.equals(localIce)) {
                gathering.put(transport, localIce);
                if (restart) {
                    localCandidates.remove(transport);
                    localComplete.remove(transport);
                }
                connection.backend().startGathering(transport, localIce);
            }
        }
    }

    /// {@return the identification tags of the BUNDLE group the current answer accepted, the tagged one first}
    private List<String> negotiatedBundle() {
        if (currentLocal == null || currentRemote == null) {
            return List.of();
        }
        var answer = currentLocal.type() == JsepType.ANSWER ? currentLocal.sdp() : currentRemote.sdp();
        return answer.bundleGroups().stream().findFirst().map(SdpAttribute.Group::mids).orElse(List.of());
    }


    /// Computes what an offer and its answer negotiated.
    private Negotiated negotiate(SessionDescription offer, SessionDescription answer, boolean localIsOfferer) {
        var local = localIsOfferer ? offer : answer;
        var remote = localIsOfferer ? answer : offer;
        var bundle = answer.bundleGroups().stream().findFirst();
        var tag = bundle.flatMap(value -> bundleTag(answer, value));
        var group = tag.isEmpty() ? List.<String>of() : bundle.get().mids();
        var remoteLite = remote.attribute(SdpAttribute.IceLite.class).isPresent();
        if (iceRole == null || remoteRestartsIce(remote)) {
            iceRole = connection.configuration().iceLite() ? IceRole.CONTROLLED
                    : remoteLite ? IceRole.CONTROLLING
                    : localIsOfferer ? IceRole.CONTROLLING : IceRole.CONTROLLED;
        }
        var transportOf = new LinkedHashMap<String, String>();
        var closed = new ArrayList<String>();
        var media = new ArrayList<Negotiated.Media>();
        Negotiated.Data data = null;
        for (var index = 0; index < answer.media().size(); index++) {
            var answerSection = answer.media().get(index);
            var mid = answerSection.mid().orElse(null);
            if (mid == null) {
                continue;
            }
            if (answerSection.isRejected()) {
                closed.add(mid);
                continue;
            }
            var transportId = group.contains(mid) ? tag.get() : mid;
            transportOf.put(mid, transportId);
            var localSection = local.media().get(index);
            var remoteSection = remote.media().get(index);
            if (answerSection.media().equals("application")) {
                var remotePort = remoteSection.attribute(SdpAttribute.SctpPort.class)
                        .map(SdpAttribute.SctpPort::port).orElse(SCTP_PORT);
                var remoteMax = remoteSection.attribute(SdpAttribute.MaxMessageSize.class)
                        .map(SdpAttribute.MaxMessageSize::size).orElse(DEFAULT_REMOTE_MAX_MESSAGE_SIZE);
                data = new Negotiated.Data(mid, transportId, SCTP_PORT, remotePort, MAX_MESSAGE_SIZE, remoteMax);
                dataMid = mid;
                continue;
            }
            var transceiver = transceiverByMid(mid);
            if (transceiver == null) {
                continue;
            }
            media.add(negotiateMedia(transceiver, mid, transportId, local, localSection, remote, remoteSection,
                    answerSection, localIsOfferer));
        }
        var transports = new ArrayList<Negotiated.Transport>();
        for (var transportId : new LinkedHashSet<>(transportOf.values())) {
            var tagged = remote.mediaByMid(transportId).orElseThrow(
                    () -> new OperationErrorException("the remote description lacks a=mid:" + transportId));
            var localTagged = local.mediaByMid(transportId).orElseThrow(
                    () -> new OperationErrorException("the local description lacks a=mid:" + transportId));
            var remoteIce = new Negotiated.IceCredentials(
                    remote.attribute(tagged, SdpAttribute.IceUfrag.class).map(SdpAttribute.IceUfrag::ufrag)
                            .orElseThrow(() -> new OperationErrorException(
                                    "the remote transport a=mid:" + transportId + " lacks a=ice-ufrag")),
                    remote.attribute(tagged, SdpAttribute.IcePwd.class).map(SdpAttribute.IcePwd::password)
                            .orElseThrow(() -> new OperationErrorException(
                                    "the remote transport a=mid:" + transportId + " lacks a=ice-pwd")));
            var candidates = new ArrayList<String>();
            var complete = false;
            for (var entry : transportOf.entrySet()) {
                if (!entry.getValue().equals(transportId)) {
                    continue;
                }
                var section = remote.mediaByMid(entry.getKey()).orElseThrow(
                        () -> new OperationErrorException("the remote description lacks a=mid:" + entry.getKey()));
                for (var candidate : section.attributes("candidate")) {
                    if (!candidates.contains(candidate)) {
                        candidates.add(candidate);
                    }
                }
                for (var candidate : remoteCandidates.getOrDefault(entry.getKey(), List.of())) {
                    if (!candidates.contains(candidate)) {
                        candidates.add(candidate);
                    }
                }
                complete |= section.hasAttribute("end-of-candidates") || remoteComplete.contains(entry.getKey());
            }
            var fingerprints = new ArrayList<>(tagged.attributes(SdpAttribute.Fingerprint.class));
            if (fingerprints.isEmpty()) {
                fingerprints.addAll(remote.attributes(SdpAttribute.Fingerprint.class));
            }
            var localSetup = local.attribute(localTagged, SdpAttribute.Setup.class).map(SdpAttribute.Setup::role)
                    .orElse(SetupRole.ACTPASS);
            var remoteSetup = remote.attribute(tagged, SdpAttribute.Setup.class).map(SdpAttribute.Setup::role)
                    .orElse(SetupRole.ACTIVE);
            var role = localIsOfferer
                    ? remoteSetup == SetupRole.PASSIVE ? DtlsRole.CLIENT : DtlsRole.SERVER
                    : localSetup == SetupRole.PASSIVE ? DtlsRole.SERVER : DtlsRole.CLIENT;
            var remoteTlsId = remote.attribute(tagged, SdpAttribute.TlsId.class).map(SdpAttribute.TlsId::id);
            var previous = negotiated == null ? Optional.<Negotiated.Transport>empty() : negotiated.transports()
                    .stream().filter(candidate -> candidate.id().equals(transportId)).findFirst();
            var dtlsRestart = previous.isPresent() && (previous.get().dtlsRole() != role
                    || !new HashSet<>(previous.get().remoteFingerprints()).equals(new HashSet<>(fingerprints))
                    || (previous.get().remoteTlsId().isPresent() && remoteTlsId.isPresent()
                    && !previous.get().remoteTlsId().equals(remoteTlsId)));
            if (dtlsRole == null || dtlsRestart) {
                dtlsRole = role;
            }
            var localTlsId = local.attribute(localTagged, SdpAttribute.TlsId.class).map(SdpAttribute.TlsId::id)
                    .orElseGet(() -> previous.map(Negotiated.Transport::localTlsId)
                            .orElseGet(() -> randomToken(TLS_ID_LENGTH)));
            var mids = transportOf.entrySet().stream().filter(entry -> entry.getValue().equals(transportId))
                    .map(Map.Entry::getKey).toList();
            transports.add(new Negotiated.Transport(transportId, mids, localIce, remoteIce, remoteLite, candidates,
                    complete, fingerprints, role, iceRole, localTlsId, remoteTlsId, dtlsRestart));
            localTransportOf.keySet().removeIf(mid -> !transportOf.containsKey(mid));
            for (var mid : mids) {
                localTransportOf.put(mid, transportId);
            }
        }
        gathering.keySet().removeIf(transport -> !transportOf.containsValue(transport));
        return new Negotiated(localIsOfferer, transports, media, Optional.ofNullable(data), closed);
    }

    /// Computes what one RTP section negotiated.
    private Negotiated.Media negotiateMedia(RtpTransceiver transceiver, String mid, String transportId,
                                            SessionDescription local, MediaDescription localSection,
                                            SessionDescription remote, MediaDescription remoteSection,
                                            MediaDescription answerSection, boolean localIsOfferer) {
        var answerDirection = answerSection.direction().orElse(MediaDirection.SENDRECV);
        var localDirection = localIsOfferer ? answerDirection.reverse() : answerDirection;
        var direction = TransceiverDirection.of(localDirection.sends(), localDirection.receives());
        var answerCodecs = remoteCodecs(answerSection);
        var offerCodecs = remoteCodecs(localIsOfferer ? localSection : remoteSection);
        var codecs = new ArrayList<Negotiated.CodecEntry>();
        var red = OptionalInt.empty();
        var ulpfec = OptionalInt.empty();
        var flexfec = OptionalInt.empty();
        Negotiated.CodecEntry telephoneEvent = null;
        for (var entry : answerCodecs) {
            var subtype = CodecCatalog.subtype(entry.codec());
            switch (subtype) {
                case CodecCatalog.RTX -> {
                }
                case CodecCatalog.RED -> red = OptionalInt.of(entry.payloadType());
                case CodecCatalog.ULPFEC -> ulpfec = OptionalInt.of(entry.payloadType());
                case CodecCatalog.FLEXFEC -> flexfec = OptionalInt.of(entry.payloadType());
                case CodecCatalog.TELEPHONE_EVENT -> {
                    if (telephoneEvent == null) {
                        telephoneEvent = entry;
                    }
                }
                default -> codecs.add(new Negotiated.CodecEntry(entry.payloadType(),
                        offerCodecs.stream().filter(offered -> offered.payloadType() == entry.payloadType())
                                .map(Negotiated.CodecEntry::codec).findFirst().orElse(entry.codec()),
                        entry.feedback(), rtxFor(answerCodecs, entry.payloadType())));
            }
        }
        var extensions = new LinkedHashMap<Integer, URI>();
        var extensionDirections = new LinkedHashMap<URI, TransceiverDirection>();
        for (var extmap : answerSection.attributes(SdpAttribute.Extmap.class)) {
            extensions.put(extmap.id(), extmap.uri());
            var answered = extmap.direction().orElse(MediaDirection.SENDRECV);
            var mine = localIsOfferer ? answered.reverse() : answered;
            extensionDirections.putIfAbsent(extmap.uri(), TransceiverDirection.of(mine.sends(), mine.receives()));
        }
        var sendLayers = new ArrayList<Negotiated.SendLayer>();
        if (direction.sends()) {
            var layers = transceiver.sender().layers();
            var localSimulcast = localSection.attribute(SdpAttribute.Simulcast.class)
                    .map(SdpAttribute.Simulcast::send).orElse(List.of());
            var remoteSimulcast = remoteSection.attribute(SdpAttribute.Simulcast.class)
                    .map(SdpAttribute.Simulcast::receive).orElse(List.of());
            if (layers.size() > 1 && !localSimulcast.isEmpty() && !remoteSimulcast.isEmpty()) {
                var accepted = new HashSet<String>();
                remoteSimulcast.forEach(alternatives -> alternatives.forEach(stream -> accepted.add(stream.rid())));
                for (var layer : layers) {
                    if (accepted.contains(layer.rid().orElseThrow())) {
                        sendLayers.add(layer);
                    }
                }
            } else {
                var first = layers.getFirst();
                sendLayers.add(new Negotiated.SendLayer(Optional.empty(), first.ssrc(), first.rtxSsrc(),
                        first.encoding()));
            }
        }
        var receiveLayers = new ArrayList<Negotiated.ReceiveLayer>();
        if (direction.receives()) {
            var simulcast = remoteSection.attribute(SdpAttribute.Simulcast.class).map(SdpAttribute.Simulcast::send)
                    .orElse(List.of());
            if (!simulcast.isEmpty()) {
                for (var alternatives : simulcast) {
                    for (var stream : alternatives) {
                        receiveLayers.add(new Negotiated.ReceiveLayer(Optional.of(stream.rid()), OptionalLong.empty(),
                                OptionalLong.empty(), stream.paused()));
                    }
                }
            } else {
                receiveLayers.add(remoteSsrcLayer(remoteSection));
            }
        }
        var remoteStreams = remoteSection.attributes(SdpAttribute.Msid.class).stream()
                .map(SdpAttribute.Msid::streamId).filter(stream -> !stream.equals("-")).distinct().toList();
        var maxBitrate = payloadBitrate(remoteSection.bandwidths(), transceiver.kind())
                .or(() -> payloadBitrate(remote.bandwidths(), transceiver.kind()))
                .map(OptionalLong::of).orElse(OptionalLong.empty());
        var reducedSize = answerSection.hasAttribute("rtcp-rsize");
        var cryptex = hasCryptex(local, localSection) && hasCryptex(remote, remoteSection);
        var ccfb = hasCongestionControlFeedback(localSection) && hasCongestionControlFeedback(remoteSection);
        return new Negotiated.Media(transceiver, mid, transportId, transceiver.kind(), direction, codecs, red, ulpfec,
                flexfec, Optional.ofNullable(telephoneEvent), extensions, reducedSize, cname, sendLayers,
                receiveLayers, remoteStreams, maxBitrate, cryptex, ccfb, extensionDirections);
    }

    /// {@return the payload bitrate cap that `b=` lines set, in bits per second: `TIAS` as is, else `AS` less the
    /// packet overhead of [#PACKET_OVERHEAD_BYTES] at the packet rate of the kind (50 per second for audio, one per
    /// [#VIDEO_PACKET_BYTES] of video), never below half the `AS` value; an empty optional when neither is set}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc3890.html RFC 3890: A Transport Independent Bandwidth Modifier for the Session Description Protocol (SDP)
    /// @spec https://www.rfc-editor.org/rfc/rfc3556.html RFC 3556: Session Description Protocol (SDP) Bandwidth Modifiers for RTP Control Protocol (RTCP) Bandwidth
    static Optional<Long> payloadBitrate(List<Bandwidth> bandwidths, MediaKind kind) {
        for (var bandwidth : bandwidths) {
            if (bandwidth.type().equals(Bandwidth.TIAS) && bandwidth.bitsPerSecond().isPresent()) {
                return Optional.of(bandwidth.bitsPerSecond().getAsLong());
            }
        }
        for (var bandwidth : bandwidths) {
            if (bandwidth.type().equals(Bandwidth.AS) && bandwidth.bitsPerSecond().isPresent()) {
                var total = bandwidth.bitsPerSecond().getAsLong();
                var packetsPerSecond = kind == MediaKind.AUDIO ? AUDIO_PACKETS_PER_SECOND
                        : Math.ceilDiv(total, VIDEO_PACKET_BYTES * 8L);
                var overhead = packetsPerSecond * PACKET_OVERHEAD_BYTES * 8L;
                return Optional.of(Math.max(total - overhead, total / 2));
            }
        }
        return Optional.empty();
    }

    /// {@return the remote stream a section without simulcast announces through `a=ssrc` and `a=ssrc-group:FID`}
    private static Negotiated.ReceiveLayer remoteSsrcLayer(MediaDescription section) {
        var groups = section.attributes(SdpAttribute.SsrcGroup.class);
        for (var group : groups) {
            if (group.semantics().equals(SdpAttribute.SsrcGroup.FID) && group.ssrcs().size() >= 2) {
                return new Negotiated.ReceiveLayer(Optional.empty(), OptionalLong.of(group.ssrcs().getFirst()),
                        OptionalLong.of(group.ssrcs().get(1)), false);
            }
        }
        var ssrcs = section.attributes(SdpAttribute.Ssrc.class);
        if (!ssrcs.isEmpty()) {
            return new Negotiated.ReceiveLayer(Optional.empty(), OptionalLong.of(ssrcs.getFirst().ssrc()),
                    OptionalLong.empty(), false);
        }
        return new Negotiated.ReceiveLayer(Optional.empty(), OptionalLong.empty(), OptionalLong.empty(), false);
    }

    /// {@return the codecs of a section, from its formats, `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines}
    static List<Negotiated.CodecEntry> remoteCodecs(MediaDescription section) {
        var feedback = section.attributes(SdpAttribute.RtcpFb.class);
        var result = new ArrayList<Negotiated.CodecEntry>();
        var kind = kindOf(section.media()).orElse(MediaKind.AUDIO);
        for (var rtp : RtpCodec.of(section)) {
            var parameters = rtp.fmtpValue().map(text -> new SdpAttribute.Fmtp(rtp.payloadType(), text).parameterMap())
                    .orElse(Map.of());
            var mime = (kind == MediaKind.AUDIO ? "audio/" : "video/") + rtp.name();
            Codec codec;
            try {
                codec = new Codec(mime, rtp.clockRate(),
                        kind == MediaKind.AUDIO ? OptionalInt.of(rtp.channelCount()) : OptionalInt.empty(),
                        lowerCaseKeys(parameters));
            } catch (IllegalArgumentException exception) {
                continue;
            }
            var fbs = new ArrayList<RtcpFeedback>();
            for (var fb : feedback) {
                if (isCongestionControlFeedback(fb)) {
                    continue;
                }
                if (fb.payloadType().isEmpty() || fb.payloadType().getAsInt() == rtp.payloadType()) {
                    var mechanism = new RtcpFeedback(fb.type(), fb.parameter());
                    if (!fbs.contains(mechanism)) {
                        fbs.add(mechanism);
                    }
                }
            }
            result.add(new Negotiated.CodecEntry(rtp.payloadType(), codec, fbs, OptionalInt.empty()));
        }
        return result;
    }

    /// {@return a parameter map with lower-case keys, in order}
    private static Map<String, String> lowerCaseKeys(Map<String, String> parameters) {
        var result = new LinkedHashMap<String, String>();
        parameters.forEach((key, value) -> result.putIfAbsent(key.toLowerCase(Locale.ROOT), value));
        return result;
    }


    /// Records a local candidate a transport gathered.
    ///
    /// @return the media section the candidate belongs to: its tag and index, or an empty optional when the transport
    ///         is no longer in use
    Optional<IceCandidateInit> localCandidate(String transportId, String candidate) {
        if (!gathering.containsKey(transportId)) {
            return Optional.empty();
        }
        var list = localCandidates.computeIfAbsent(transportId, ignored -> new ArrayList<>());
        if (!list.contains(candidate)) {
            list.add(candidate);
        }
        return sectionOf(transportId).map(index -> new IceCandidateInit("candidate:" + candidate,
                Optional.of(transportId), OptionalInt.of(index),
                Optional.ofNullable(gathering.get(transportId)).map(Negotiated.IceCredentials::usernameFragment)));
    }

    /// Records that a transport finished gathering.
    void localGatheringComplete(String transportId) {
        localComplete.add(transportId);
    }

    /// {@return the index of the section tagged `mid` in the latest local description}
    private Optional<Integer> sectionOf(String mid) {
        var description = pendingLocal != null ? pendingLocal : currentLocal;
        if (description == null) {
            return Optional.empty();
        }
        var sections = description.sdp().media();
        for (var index = 0; index < sections.size(); index++) {
            if (sections.get(index).mid().filter(mid::equals).isPresent()) {
                return Optional.of(index);
            }
        }
        return Optional.empty();
    }

    /// Adds a trickled remote candidate, the JSEP `addIceCandidate`.
    ///
    /// @return the transport the candidate belongs to and the candidate text, or an empty optional when the
    ///         transport does not run yet and the candidate waits for the answer
    /// @throws InvalidStateException   if no remote description is applied
    /// @throws OperationErrorException if the candidate matches no section or carries another username fragment
    Optional<Map.Entry<String, String>> addIceCandidate(IceCandidateInit init) {
        var description = pendingRemote != null ? pendingRemote : currentRemote;
        if (description == null) {
            throw new InvalidStateException("addIceCandidate needs a remote description");
        }
        var sections = description.sdp().media();
        MediaDescription section = null;
        if (init.sdpMid().isPresent()) {
            section = description.sdp().mediaByMid(init.sdpMid().get()).orElse(null);
        } else if (init.sdpMLineIndex().isPresent() && init.sdpMLineIndex().getAsInt() < sections.size()) {
            section = sections.get(init.sdpMLineIndex().getAsInt());
        }
        if (section == null || section.mid().isEmpty()) {
            throw new OperationErrorException("the candidate matches no media section");
        }
        var mid = section.mid().get();
        var ufrag = description.sdp().attribute(section, SdpAttribute.IceUfrag.class)
                .map(SdpAttribute.IceUfrag::ufrag);
        if (init.usernameFragment().isPresent() && !init.usernameFragment().equals(ufrag)) {
            throw new OperationErrorException("the candidate belongs to another ICE generation");
        }
        if (section.isRejected()) {
            return Optional.empty();
        }
        var transport = negotiated == null ? null : negotiated.transports().stream()
                .filter(candidate -> candidate.mids().contains(mid)).map(Negotiated.Transport::id).findFirst()
                .orElse(null);
        if (init.isEndOfCandidates()) {
            remoteComplete.add(mid);
            return transport == null ? Optional.empty() : Optional.of(Map.entry(transport, ""));
        }
        var value = init.candidateValue();
        if (value.isEmpty() || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new OperationErrorException("malformed candidate");
        }
        var list = remoteCandidates.computeIfAbsent(mid, ignored -> new ArrayList<>());
        if (!list.contains(value)) {
            list.add(value);
        }
        return transport == null ? Optional.empty() : Optional.of(Map.entry(transport, value));
    }


    /// {@return whether the connection needs a new offer/answer exchange, the W3C "check if negotiation is needed"}
    boolean isNegotiationNeeded() {
        if (state != SignalingState.STABLE) {
            return false;
        }
        if (iceRestartRequested) {
            return true;
        }
        var description = currentLocal;
        if (dataRequested && (description == null || description.sdp().media().stream()
                .noneMatch(section -> section.media().equals("application") && !section.isRejected()))) {
            return true;
        }
        for (var transceiver : connection.transceiverList()) {
            if (transceiver.stopped) {
                continue;
            }
            if (transceiver.stopping) {
                if (transceiver.mid != null && description != null && description.sdp().mediaByMid(transceiver.mid)
                        .filter(section -> !section.isRejected()).isPresent()) {
                    return true;
                }
                continue;
            }
            if (transceiver.mid == null || description == null) {
                return true;
            }
            var section = description.sdp().mediaByMid(transceiver.mid).orElse(null);
            if (section == null) {
                return true;
            }
            if (transceiver.direction.sends()) {
                var announced = section.attributes(SdpAttribute.Msid.class).stream().map(SdpAttribute.Msid::streamId)
                        .filter(stream -> !stream.equals("-")).collect(java.util.stream.Collectors.toSet());
                if (!announced.equals(Set.copyOf(transceiver.sender().streams()))) {
                    return true;
                }
            }
            var localDirection = description.sdp().direction(section);
            var wanted = toSdp(transceiver.direction);
            if (description.type() == JsepType.OFFER) {
                var remoteSection = currentRemote.sdp().mediaByMid(transceiver.mid);
                var remoteDirection = remoteSection.map(remoteValue -> currentRemote.sdp().direction(remoteValue))
                        .orElse(MediaDirection.INACTIVE);
                if (localDirection != wanted && remoteDirection.reverse() != wanted) {
                    return true;
                }
            } else {
                var offered = currentRemote.sdp().mediaByMid(transceiver.mid)
                        .map(remoteValue -> currentRemote.sdp().direction(remoteValue).reverse())
                        .orElse(MediaDirection.INACTIVE);
                if (localDirection != wanted.intersect(offered)) {
                    return true;
                }
            }
        }
        return false;
    }


    /// {@return the transceiver bound to `mid`, or `null`}
    private RtpTransceiver transceiverByMid(String mid) {
        for (var transceiver : connection.transceiverList()) {
            if (mid.equals(transceiver.mid)) {
                return transceiver;
            }
        }
        return null;
    }

    /// {@return every identification tag in use in a description or by a transceiver}
    private Set<String> usedMids() {
        var result = usedMidsExcludingData();
        if (dataMid != null) {
            result.add(dataMid);
        }
        return result;
    }

    /// {@return every identification tag in use, the data section's excepted}
    private Set<String> usedMidsExcludingData() {
        var result = new HashSet<String>();
        for (var description : new Description[]{currentLocal, pendingLocal, currentRemote, pendingRemote}) {
            if (description != null) {
                for (var section : description.sdp().media()) {
                    section.mid().filter(mid -> !mid.equals(dataMid)).ifPresent(result::add);
                }
            }
        }
        for (var transceiver : connection.transceiverList()) {
            if (transceiver.mid != null) {
                result.add(transceiver.mid);
            }
        }
        return result;
    }

    /// {@return the smallest decimal identification tag not in `used`, which is then added to it}
    private static String nextMid(Set<String> used) {
        for (var candidate = 0; ; candidate++) {
            var mid = Integer.toString(candidate);
            if (used.add(mid)) {
                return mid;
            }
        }
    }

    /// {@return the payload type of a codec configuration, allocating one when it has none}
    private int payloadType(Codec codec) {
        return payloadType(CodecCatalog.key(codec), codec);
    }

    /// {@return the payload type of the configuration named `key`, allocating one when it has none}
    private int payloadType(String key, Codec codec) {
        var existing = payloadTypes.get(key);
        if (existing != null) {
            return existing;
        }
        var used = new HashSet<>(payloadTypes.values());
        var preferred = key.startsWith("rtx:") ? OptionalInt.empty() : CodecCatalog.preferredPayloadType(codec);
        int chosen;
        if (preferred.isPresent() && !used.contains(preferred.getAsInt())) {
            chosen = preferred.getAsInt();
        } else {
            chosen = -1;
            for (var candidate = 96; candidate <= 127 && chosen < 0; candidate++) {
                if (!used.contains(candidate) && !reserved(candidate)) {
                    chosen = candidate;
                }
            }
            for (var candidate = 35; candidate <= 63 && chosen < 0; candidate++) {
                if (!used.contains(candidate)) {
                    chosen = candidate;
                }
            }
            if (chosen < 0) {
                throw new OperationErrorException("no dynamic payload type left");
            }
        }
        payloadTypes.put(key, chosen);
        return chosen;
    }

    /// {@return whether a payload type is kept for a codec browsers give it}
    private static boolean reserved(int payloadType) {
        return payloadType == 111 || payloadType == 126 || payloadType == 110;
    }

    /// Records the payload type an offer gave a codec, so later offers keep it.
    private void adoptPayloadType(Codec codec, int payloadType) {
        var key = CodecCatalog.key(codec);
        if (!payloadTypes.containsKey(key) && !payloadTypes.containsValue(payloadType)) {
            payloadTypes.put(key, payloadType);
        }
    }

    /// {@return the identifier of a header extension, allocating one when it has none}
    private int extensionId(URI uri) {
        var existing = extensionIds.get(uri);
        if (existing != null) {
            return existing;
        }
        var used = new HashSet<>(extensionIds.values());
        for (var candidate = 1; candidate <= 255; candidate++) {
            if (candidate != 15 && !used.contains(candidate)) {
                extensionIds.put(uri, candidate);
                return candidate;
            }
        }
        throw new OperationErrorException("no header extension id left");
    }

    /// {@return the ICE credentials of a description: those of its first section that has them}
    private static Optional<Negotiated.IceCredentials> iceCredentials(SessionDescription description) {
        for (var section : description.media()) {
            var ufrag = description.attribute(section, SdpAttribute.IceUfrag.class);
            var pwd = description.attribute(section, SdpAttribute.IcePwd.class);
            if (ufrag.isPresent() && pwd.isPresent()) {
                return Optional.of(new Negotiated.IceCredentials(ufrag.get().ufrag(), pwd.get().password()));
            }
        }
        return Optional.empty();
    }

    /// {@return whether a remote description carries other ICE credentials than the current remote description}
    private boolean remoteRestartsIce(SessionDescription remote) {
        if (currentRemote == null) {
            return false;
        }
        var previous = iceCredentials(currentRemote.sdp());
        var next = iceCredentials(remote);
        return previous.isPresent() && next.isPresent() && !previous.equals(next);
    }

    /// {@return the credentials of the next local description: the current ones, unless `restart` asks for new ones
    /// or there are none yet; repeated calls return the same new credentials until a description applies them}
    private Negotiated.IceCredentials iceForNext(boolean restart) {
        if (!restart && localIce != null) {
            return localIce;
        }
        if (nextIce == null || nextIce.equals(localIce)) {
            nextIce = newCredentials();
        }
        return nextIce;
    }

    /// {@return fresh ICE credentials: a 4-character username fragment and a 24-character password}
    private Negotiated.IceCredentials newCredentials() {
        return new Negotiated.IceCredentials(randomToken(4), randomToken(24));
    }

    /// {@return `length` random ICE characters}
    private String randomToken(int length) {
        var builder = new StringBuilder(length);
        for (var index = 0; index < length; index++) {
            builder.append(ICE_CHARS.charAt(random.nextInt(ICE_CHARS.length())));
        }
        return builder.toString();
    }

    /// {@return the parsed description}
    ///
    /// @throws OperationErrorException if the text is not a session description
    private static SessionDescription parse(String text) {
        try {
            return SessionDescription.parse(Objects.requireNonNull(text, "sdp cannot be null"));
        } catch (SdpFormatException exception) {
            throw new OperationErrorException("malformed session description: " + exception.getMessage(), exception);
        }
    }

    /// {@return whether a protocol is one of the DTLS-SRTP profiles, the only RTP profiles a peer connection
    /// negotiates}
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
    /// @spec https://www.rfc-editor.org/rfc/rfc7850.html RFC 7850: Registering Values of the SDP 'proto' Field for Transporting RTP Media over TCP under Various RTP Profiles
    static boolean isDtlsSrtp(String protocol) {
        return DTLS_SRTP_PROTOCOLS.contains(protocol);
    }

    /// {@return whether this side can accept a media section: audio or video over a DTLS-SRTP profile, or the data
    /// section over SCTP; every other section is answered with port `0`}
    static boolean isSupported(MediaDescription section) {
        return section.media().equals("application") ? isSctp(section.protocol())
                : kindOf(section.media()).isPresent() && isDtlsSrtp(section.protocol());
    }

    /// {@return the identification tag of the section that carries the transport of a BUNDLE group: the first
    /// section the group names that is present, not rejected, has a non-zero port and that this side can accept, or
    /// an empty optional when there is none}
    ///
    /// The validator of remote descriptions and the negotiation both read the tag from here, so a description the
    /// validator accepted always has the transport attributes the negotiation reads.
    ///
    /// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
    static Optional<String> bundleTag(SessionDescription description, SdpAttribute.Group group) {
        for (var mid : group.mids()) {
            var section = description.mediaByMid(mid);
            if (section.isPresent() && !section.get().isRejected() && section.get().port() != 0
                    && isSupported(section.get())) {
                return Optional.of(mid);
            }
        }
        return Optional.empty();
    }

    /// {@return whether a protocol carries SCTP over DTLS}
    static boolean isSctp(String protocol) {
        return protocol.equals("UDP/DTLS/SCTP") || protocol.equals("TCP/DTLS/SCTP") || protocol.equals("DTLS/SCTP");
    }

    /// {@return the media kind of an `m=` media type}
    static Optional<MediaKind> kindOf(String media) {
        return switch (media) {
            case "audio" -> Optional.of(MediaKind.AUDIO);
            case "video" -> Optional.of(MediaKind.VIDEO);
            default -> Optional.empty();
        };
    }

    /// {@return the `m=` media type of a media kind}
    static String kindName(MediaKind kind) {
        return kind == MediaKind.AUDIO ? "audio" : "video";
    }

    /// {@return the SDP direction of a transceiver direction, `STOPPED` mapping to `inactive`}
    static MediaDirection toSdp(TransceiverDirection direction) {
        return MediaDirection.of(direction.sends(), direction.receives());
    }
}
