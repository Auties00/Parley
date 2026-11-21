package com.github.auties00.parley.peer;

import java.net.URI;
import java.util.Objects;

/// A negotiated RTP header extension, the W3C `RTCRtpHeaderExtensionParameters`.
///
/// @param uri       the extension URI
/// @param id        the identifier negotiated for it, `1..255`
/// @param encrypted whether the extension is encrypted
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public record RtpHeaderExtensionParameters(URI uri, int id, boolean encrypted) {
    /// Creates the parameters.
    ///
    /// @param uri       the extension URI
    /// @param id        the identifier
    /// @param encrypted whether the extension is encrypted
    /// @throws IllegalArgumentException if `id` is outside `1..255`
    public RtpHeaderExtensionParameters {
        Objects.requireNonNull(uri, "uri cannot be null");
        if (id < 1 || id > 255) {
            throw new IllegalArgumentException("extension id out of range: " + id);
        }
    }
}
