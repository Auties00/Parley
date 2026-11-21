package com.github.auties00.parley.peer;

import java.net.URI;
import java.util.Objects;

/// A header extension a connection can negotiate, with the direction a transceiver offers it in, the W3C
/// `RTCRtpHeaderExtensionCapability`.
///
/// A direction other than `SENDRECV` is written on the `a=extmap` line; `STOPPED` keeps the extension out of the
/// descriptions altogether.
///
/// @param uri       the extension URI
/// @param direction the direction to negotiate it in, `STOPPED` for an extension that is not negotiated
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.w3.org/TR/webrtc-extensions/ WebRTC Extensions
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public record RtpHeaderExtensionCapability(URI uri, TransceiverDirection direction) {
    /// Creates the capability.
    ///
    /// @param uri       the extension URI
    /// @param direction the direction
    public RtpHeaderExtensionCapability {
        Objects.requireNonNull(uri, "uri cannot be null");
        Objects.requireNonNull(direction, "direction cannot be null");
    }

    /// Creates a capability negotiated in both directions.
    ///
    /// @param uri the extension URI
    public RtpHeaderExtensionCapability(URI uri) {
        this(uri, TransceiverDirection.SENDRECV);
    }

    /// {@return the capability of the extension named by `uri`, negotiated in both directions}
    ///
    /// @param uri the extension URI text
    /// @throws IllegalArgumentException if `uri` is not a URI
    public static RtpHeaderExtensionCapability of(String uri) {
        return new RtpHeaderExtensionCapability(URI.create(uri));
    }

    /// {@return a copy with another direction}
    ///
    /// @param newDirection the direction, `STOPPED` to keep the extension out of the next negotiation
    public RtpHeaderExtensionCapability withDirection(TransceiverDirection newDirection) {
        return new RtpHeaderExtensionCapability(uri, newDirection);
    }
}
