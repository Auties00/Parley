package com.github.auties00.parley.dtls;

/// The lifecycle states of a [DtlsTransport], the values of the W3C `RTCDtlsTransportState`.
///
/// A transport moves from [#NEW] to [#CONNECTING] when its handshake starts, then to [#CONNECTED] or [#FAILED]; a
/// connected transport ends in [#CLOSED] when either side sends `close_notify`, or in [#FAILED] on a fatal alert.
///
/// @spec https://www.w3.org/TR/webrtc/#rtcdtlstransportstate-enum WebRTC: Real-Time Communication in Browsers
public enum DtlsState {
    /// The handshake has not started.
    NEW,

    /// The handshake is running.
    CONNECTING,

    /// The handshake completed and the association carries data.
    CONNECTED,

    /// The association was closed by either side with `close_notify`, or locally.
    CLOSED,

    /// The handshake failed or the association received a fatal alert.
    FAILED
}
