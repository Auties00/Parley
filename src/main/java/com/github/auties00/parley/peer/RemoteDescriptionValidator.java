package com.github.auties00.parley.peer;

import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.sdp.SessionDescription;
import com.github.auties00.parley.sdp.SetupRole;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/// Checks a remote description before it is applied.
///
/// A description that breaks the SDP grammar of an attribute the transports need, lacks an identification tag, ICE
/// credentials, a fingerprint or `a=rtcp-mux`, or misuses BUNDLE fails with an [OperationErrorException]; an answer
/// whose sections do not match the pending offer fails with an [InvalidAccessException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8839.html RFC 8839: Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)
/// @spec https://www.rfc-editor.org/rfc/rfc8122.html RFC 8122: Connection-Oriented Media Transport over the Transport Layer Security (TLS) Protocol in the Session Description Protocol (SDP)
final class RemoteDescriptionValidator {
    /// The attributes whose malformed values make a description unusable.
    private static final Set<String> CRITICAL = Set.of("mid", "group", "ice-ufrag", "ice-pwd", "fingerprint",
            "setup", "sctp-port", "max-message-size");
    /// The characters of an ICE username fragment or password.
    private static final String ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private RemoteDescriptionValidator() {
    }

    /// Validates a remote description.
    ///
    /// @param description the description
    /// @param type        its type
    /// @param localOffer  the pending local offer it answers, or `null` for an offer
    static void validate(SessionDescription description, JsepType type, SessionDescription localOffer) {
        if (description.media().isEmpty() && (localOffer == null || !localOffer.media().isEmpty())) {
            throw new OperationErrorException("the description has no media section");
        }
        critical(description.typedAttributes(), "the session level");
        var mids = new HashSet<String>();
        for (var index = 0; index < description.media().size(); index++) {
            var section = description.media().get(index);
            critical(section.typedAttributes(), "media section " + index);
            var mid = section.mid();
            if (mid.isEmpty() && !section.isRejected()) {
                throw new OperationErrorException("media section " + index + " has no a=mid");
            }
            if (mid.isPresent() && !mids.add(mid.get())) {
                throw new OperationErrorException("duplicate a=mid:" + mid.get());
            }
        }
        var answer = type != JsepType.OFFER;
        var grouped = new HashSet<String>();
        var tags = new HashSet<String>();
        for (var group : description.bundleGroups()) {
            String tag = null;
            for (var mid : group.mids()) {
                if (!mids.contains(mid)) {
                    throw new OperationErrorException("a=group:BUNDLE names an unknown a=mid:" + mid);
                }
                if (!grouped.add(mid)) {
                    throw new OperationErrorException("a=mid:" + mid + " is in two BUNDLE groups");
                }
                var section = description.mediaByMid(mid).orElseThrow();
                if (tag == null && !section.isRejected() && section.port() != 0) {
                    tag = mid;
                }
            }
            if (tag != null) {
                tags.add(tag);
            }
        }
        for (var index = 0; index < description.media().size(); index++) {
            var section = description.media().get(index);
            var where = "media section " + index;
            if (answer && section.hasAttribute("bundle-only")) {
                throw new OperationErrorException(where + ": an answer cannot use a=bundle-only");
            }
            if (section.isRejected()) {
                continue;
            }
            var mid = section.mid().orElseThrow();
            if (JsepEngine.isRtp(section.protocol()) && !section.hasAttribute("rtcp-mux")) {
                throw new OperationErrorException(where + " lacks a=rtcp-mux, which the require policy needs");
            }
            var ownsTransport = !grouped.contains(mid) || tags.contains(mid);
            if (ownsTransport) {
                checkTransport(description, section, where, answer);
            }
        }
        if (localOffer != null) {
            checkAnswersOffer(description, localOffer);
        }
    }

    /// Fails for a malformed attribute the transports need.
    private static void critical(List<SdpAttribute> attributes, String where) {
        for (var attribute : attributes) {
            if (attribute instanceof SdpAttribute.Invalid invalid && CRITICAL.contains(invalid.name())) {
                throw new OperationErrorException(where + ": malformed a=" + invalid.name() + " (" + invalid.reason()
                        + ")");
            }
        }
    }

    /// Checks the ICE and DTLS attributes of a section that carries a transport.
    private static void checkTransport(SessionDescription description, MediaDescription section, String where,
                                       boolean answer) {
        var ufrag = description.attribute(section, SdpAttribute.IceUfrag.class)
                .orElseThrow(() -> new OperationErrorException(where + " lacks a=ice-ufrag"));
        var pwd = description.attribute(section, SdpAttribute.IcePwd.class)
                .orElseThrow(() -> new OperationErrorException(where + " lacks a=ice-pwd"));
        if (!iceToken(ufrag.ufrag(), 4) || !iceToken(pwd.password(), 22)) {
            throw new OperationErrorException(where + ": malformed ICE credentials");
        }
        var dtls = section.protocol().contains("TLS") || section.protocol().contains("DTLS");
        if (dtls && section.attributes(SdpAttribute.Fingerprint.class).isEmpty()
                && description.attributes(SdpAttribute.Fingerprint.class).isEmpty()) {
            throw new OperationErrorException(where + " lacks a=fingerprint");
        }
        var setup = description.attribute(section, SdpAttribute.Setup.class).map(SdpAttribute.Setup::role);
        if (answer && setup.isPresent() && setup.get() != SetupRole.ACTIVE && setup.get() != SetupRole.PASSIVE) {
            throw new OperationErrorException(where + ": an answer must use a=setup:active or passive");
        }
        if (setup.isPresent() && setup.get() == SetupRole.HOLDCONN) {
            throw new OperationErrorException(where + ": a=setup:holdconn is not supported");
        }
    }

    /// {@return whether `value` is 4 (or `min`) to 256 ICE characters}
    private static boolean iceToken(String value, int min) {
        if (value.length() < min || value.length() > 256) {
            return false;
        }
        for (var index = 0; index < value.length(); index++) {
            if (ICE_CHARS.indexOf(value.charAt(index)) < 0) {
                return false;
            }
        }
        return true;
    }

    /// Checks that an answer has the sections of the offer, in order.
    private static void checkAnswersOffer(SessionDescription answer, SessionDescription offer) {
        if (answer.media().size() != offer.media().size()) {
            throw new InvalidAccessException("the answer has " + answer.media().size() + " media sections, the offer "
                    + offer.media().size());
        }
        for (var index = 0; index < offer.media().size(); index++) {
            var offered = offer.media().get(index);
            var answered = answer.media().get(index);
            if (!offered.media().equals(answered.media())) {
                throw new InvalidAccessException("media section " + index + " changed its media type");
            }
            if (!answered.isRejected() && !offered.mid().equals(answered.mid())) {
                throw new InvalidAccessException("media section " + index + " changed its a=mid");
            }
        }
        var offeredGroups = new HashSet<String>();
        offer.bundleGroups().forEach(group -> offeredGroups.addAll(group.mids()));
        for (var group : answer.bundleGroups()) {
            for (var mid : group.mids()) {
                if (!offeredGroups.contains(mid)) {
                    throw new InvalidAccessException("the answer bundles a=mid:" + mid + ", which the offer did not");
                }
            }
        }
    }
}
