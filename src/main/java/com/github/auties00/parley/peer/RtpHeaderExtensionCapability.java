package com.github.auties00.parley.peer;

import java.net.URI;
import java.util.Objects;

/// A header extension a connection can negotiate, the W3C `RTCRtpHeaderExtensionCapability`.
///
/// @param uri the extension URI
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public record RtpHeaderExtensionCapability(URI uri) {
    /// Creates the capability.
    ///
    /// @param uri the extension URI
    public RtpHeaderExtensionCapability {
        Objects.requireNonNull(uri, "uri cannot be null");
    }

    /// {@return the capability of the extension named by `uri`}
    ///
    /// @param uri the extension URI text
    /// @throws IllegalArgumentException if `uri` is not a URI
    public static RtpHeaderExtensionCapability of(String uri) {
        return new RtpHeaderExtensionCapability(URI.create(uri));
    }
}
