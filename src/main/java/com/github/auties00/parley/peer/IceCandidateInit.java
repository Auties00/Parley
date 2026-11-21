package com.github.auties00.parley.peer;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// An ICE candidate as signaling carries it, the W3C `RTCIceCandidateInit`.
///
/// A trickled candidate names the media section it belongs to by its identification tag, its index, or both; the tag
/// wins when both are present. An empty candidate string signals the end of candidates for that section.
///
/// @param candidate        the `candidate:` attribute text, with or without its `candidate:` prefix; empty for the
///                         end of candidates
/// @param sdpMid           the identification tag of the media section, or an empty optional
/// @param sdpMLineIndex    the index of the media section, or an empty optional
/// @param usernameFragment the ICE username fragment the candidate belongs to, or an empty optional to mean the
///                         current one
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8840.html RFC 8840: A Session Initiation Protocol (SIP) Usage for Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (Trickle ICE)
public record IceCandidateInit(String candidate, Optional<String> sdpMid, OptionalInt sdpMLineIndex,
                               Optional<String> usernameFragment) {
    /// Creates a candidate.
    ///
    /// @param candidate        the candidate text
    /// @param sdpMid           the media section tag, or an empty optional
    /// @param sdpMLineIndex    the media section index, or an empty optional
    /// @param usernameFragment the username fragment, or an empty optional
    /// @throws IllegalArgumentException if both `sdpMid` and `sdpMLineIndex` are empty, or the index is negative
    public IceCandidateInit {
        Objects.requireNonNull(candidate, "candidate cannot be null");
        Objects.requireNonNull(sdpMid, "sdpMid cannot be null");
        Objects.requireNonNull(sdpMLineIndex, "sdpMLineIndex cannot be null");
        Objects.requireNonNull(usernameFragment, "usernameFragment cannot be null");
        if (sdpMid.isEmpty() && sdpMLineIndex.isEmpty()) {
            throw new IllegalArgumentException("a candidate needs sdpMid or sdpMLineIndex");
        }
        if (sdpMLineIndex.isPresent() && sdpMLineIndex.getAsInt() < 0) {
            throw new IllegalArgumentException("negative sdpMLineIndex");
        }
    }

    /// {@return a candidate for the media section tagged `sdpMid`}
    ///
    /// @param candidate the candidate text
    /// @param sdpMid    the media section tag
    public static IceCandidateInit of(String candidate, String sdpMid) {
        return new IceCandidateInit(candidate, Optional.of(sdpMid), OptionalInt.empty(), Optional.empty());
    }

    /// {@return whether this marks the end of candidates rather than carrying one}
    public boolean isEndOfCandidates() {
        return candidate.isBlank();
    }

    /// {@return the candidate text without its `candidate:` prefix}
    public String candidateValue() {
        var text = candidate.strip();
        return text.startsWith("candidate:") ? text.substring("candidate:".length()) : text;
    }
}
