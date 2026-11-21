/// Implements the RTP payload formats of the codecs WebRTC uses: how an encoded frame is split into RTP payloads and
/// read back, without ever encoding or decoding media.
///
/// [PayloadFormat#of(com.github.auties00.parley.media.Codec)] gives the format of a codec; a format makes a
/// [Packetizer] for an outgoing stream and a [Depacketizer] for an incoming one, and answers per-packet questions
/// (keyframe, duration) for jitter buffers and forwarding units. The formats are Opus ([OpusFormat]), the simple audio
/// codecs ([AudioFormat], with the [G711] companding tables), comfort noise ([ComfortNoiseFormat]), DTMF
/// ([TelephoneEventFormat], with the [DtmfToneSequence] sender timing and the [TelephoneEventDetector] receiver), VP8
/// ([Vp8Format]), VP9 ([Vp9Format]), H.264 ([H264Format]), H.265 ([H265Format]), AV1 ([Av1Format]) and an opaque
/// passthrough ([GenericFormat]). [Vp8PayloadRewriter] and [Vp9PayloadRewriter] keep picture ids continuous when a
/// forwarding unit switches between simulcast streams.
///
/// Formats are immutable and safe to share; packetizers, depacketizers and rewriters belong to one stream and are not
/// safe for concurrent use.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
/// @spec https://www.rfc-editor.org/rfc/rfc3389.html RFC 3389: Real-time Transport Protocol (RTP) Payload for Comfort Noise (CN)
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
/// @spec https://www.rfc-editor.org/rfc/rfc7587.html RFC 7587: RTP Payload Format for the Opus Speech and Audio Codec
/// @spec https://www.rfc-editor.org/rfc/rfc7741.html RFC 7741: RTP Payload Format for VP8 Video
/// @spec https://www.rfc-editor.org/rfc/rfc7798.html RFC 7798: RTP Payload Format for High Efficiency Video Coding (HEVC)
/// @spec https://www.rfc-editor.org/rfc/rfc9628.html RFC 9628: RTP Payload Format for VP9 Video
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
/// @spec https://www.w3.org/TR/webrtc/#rtcdtmfsender-interface W3C WebRTC: RTCDTMFSender interface
package com.github.auties00.parley.payload;
