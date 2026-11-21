package com.github.auties00.parley.peer;

/// The options of [PeerConnection#createOffer(OfferOptions)], the W3C `RTCOfferOptions`.
///
/// @param iceRestart whether the offer restarts ICE with fresh credentials on every transport, as
///                   [PeerConnection#restartIce()] does
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public record OfferOptions(boolean iceRestart) {
    /// The default options: no ICE restart.
    public static final OfferOptions DEFAULT = new OfferOptions(false);
}
