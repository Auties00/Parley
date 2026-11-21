package com.github.auties00.parley.datachannel;

/// The SCTP payload protocol identifiers WebRTC assigns, from the IANA SCTP Payload Protocol Identifiers registry.
///
/// SCTP cannot carry an empty message, so an empty string or binary message is sent as one zero byte under its own
/// identifier.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html#section-8 RFC 8831: WebRTC Data Channels, IANA Considerations
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html#section-8.1 RFC 8832: WebRTC Data Channel Establishment Protocol, SCTP Payload Protocol Identifier
final class PayloadProtocol {
    /// A Data Channel Establishment Protocol message.
    static final long DCEP = 50;

    /// A UTF-8 string message.
    static final long STRING = 51;

    /// A partial binary message, deprecated; received ones are read as binary.
    static final long BINARY_PARTIAL = 52;

    /// A binary message.
    static final long BINARY = 53;

    /// A partial string message, deprecated; received ones are read as text.
    static final long STRING_PARTIAL = 54;

    /// An empty string message.
    static final long STRING_EMPTY = 56;

    /// An empty binary message.
    static final long BINARY_EMPTY = 57;

    private PayloadProtocol() {
    }
}
