/// Provides WebRTC data channels: [SctpTransport], the SCTP association that runs over a DTLS transport's
/// application data, and the [DataChannel]s it carries, each a bidirectional, message-oriented channel with its own
/// ordering and reliability, opened in band with the Data Channel Establishment Protocol or negotiated out of band.
///
/// {@snippet lang = java :
/// var sctp = SctpTransport.over(dtls, SctpConfig.defaults());
/// sctp.start(DtlsRole.CLIENT, remoteSctpPort, remoteMaxMessageSize, Duration.ofSeconds(10));
/// try (var chat = sctp.createDataChannel("chat", DataChannelInit.reliable())) {
///     chat.send("hello");
///     switch (chat.receive()) {
///         case DataChannelMessage.Text(var text) -> System.out.println(text);
///         case DataChannelMessage.Binary(var bytes) -> System.out.println(bytes.remaining() + " bytes");
///     }
/// }
/// }
///
/// # Threading
///
/// Every type is safe for use from several threads. Blocking calls ([DataChannel#receive()],
/// [SctpTransport#acceptDataChannel()], the sends while the association's send buffer is full) block the calling
/// thread, which is meant to be a virtual thread, and are interruptible. The transport reads the association on one
/// thread from the configured [java.util.concurrent.ThreadFactory] and dispatches each message to its channel.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8831.html RFC 8831: WebRTC Data Channels
/// @spec https://www.rfc-editor.org/rfc/rfc8832.html RFC 8832: WebRTC Data Channel Establishment Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc8261.html RFC 8261: Datagram Transport Layer Security (DTLS) Encapsulation of SCTP Packets
/// @spec https://www.rfc-editor.org/rfc/rfc8841.html RFC 8841: Session Description Protocol (SDP) Offer/Answer Procedures for Stream Control Transmission Protocol (SCTP) over Datagram Transport Layer Security (DTLS) Transport
/// @spec https://www.w3.org/TR/webrtc/#peer-to-peer-data-api WebRTC: Real-Time Communication in Browsers, Peer-to-peer Data API
package com.github.auties00.parley.datachannel;
