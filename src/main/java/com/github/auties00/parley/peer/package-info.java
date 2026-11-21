/// Provides the W3C WebRTC object model: [PeerConnection], which negotiates media and data with a remote peer through
/// JSEP offers and answers and runs the transports the negotiation calls for, with its transceivers, senders,
/// receivers, tracks, transport views and events.
///
/// # Overview
///
/// - [PeerConnection] is the `RTCPeerConnection`, created from a [Configuration] (`RTCConfiguration`). The
///   application carries descriptions ([JsepDescription]) and candidates ([IceCandidateInit]) over its own signaling
///   channel.
/// - [RtpTransceiver] pairs an [RtpSender] and an [RtpReceiver] for one media section. Media flows as encoded frames:
///   the application writes them into a [LocalTrack] ([LocalAudioTrack], [LocalVideoTrack]) and reads them from a
///   [RemoteTrack]; an SFU forwards RTP packets from a remote track through a [LocalForwardedTrack] instead.
/// - [FrameTransform] is the encoded transform (end-to-end encryption such as SFrame), and [DtmfSender] sends
///   telephone events.
/// - [PeerDtlsTransport], [PeerIceTransport] and [PeerSctpTransport] are read-only views of the running transports.
/// - Every application-level object raises its events through `events()`, an
///   [com.github.auties00.parley.event.EventStream]: [PeerConnectionEvent], [LocalTrackEvent], [RemoteTrackEvent],
///   [PeerIceTransportEvent] and [DtmfSender.ToneChange]. The first stream opened on an object receives everything it
///   raised since its creation, so the order of the calls below loses nothing.
/// - Misuse throws the W3C exceptions: [InvalidStateException] and [OperationErrorException] (both
///   [IllegalStateException]s), [InvalidAccessException] and [InvalidModificationException] (both
///   [IllegalArgumentException]s).
///
/// {@snippet lang = java :
/// var pc = PeerConnection.create(Configuration.builder()
///         .iceServers(IceServer.of("stun:stun.example.org"))
///         .build());
/// var events = pc.events();
/// var camera = LocalTrack.video("camera");
/// pc.addTrack(camera, "stream-1");
/// pc.setLocalDescription();                                    // creates and applies the offer
/// signaling.sendOffer(pc.localDescription().orElseThrow().sdp());
/// pc.setRemoteDescription(JsepDescription.answer(signaling.receiveAnswer()));
/// Thread.ofVirtual().start(() -> {
///     for (var event : events) {
///         switch (event) {
///             case PeerConnectionEvent.IceCandidate candidate -> signaling.sendCandidate(candidate.candidate());
///             case PeerConnectionEvent.Track track -> play(track.receiver().track());
///             default -> { }
///         }
///     }
/// });
/// if (pc.awaitConnectionState(PeerConnectionState.CONNECTED, Duration.ofSeconds(10))) {
///     camera.write(encoder.encode(picture));
/// }
/// }
///
/// # Threading
///
/// Every public method is safe for concurrent use. Parley starts its threads through the configuration's
/// [java.util.concurrent.ThreadFactory]; the tracks and DTMF senders start none of their own. Only methods named
/// `await...` and the event streams' `next` wait; they take a [java.time.Duration] or can be interrupted.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
/// @spec https://www.w3.org/TR/webrtc-stats/ Identifiers for WebRTC's Statistics API
package com.github.auties00.parley.peer;
