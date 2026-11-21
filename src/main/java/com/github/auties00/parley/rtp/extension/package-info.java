/// Provides the RTP header extensions WebRTC endpoints negotiate: the per-session id to URI mapping
/// ([HeaderExtensionMap], with the URIs in [HeaderExtensionUris]) and a typed, immutable value per extension (the
/// sealed [HeaderExtension] family), each with its parser and writer.
///
/// | Value | URI constant | Specification |
/// |---|---|---|
/// | [Mid] | [HeaderExtensionUris#MID] | RFC 8843 |
/// | [RtpStreamId], [RepairedRtpStreamId] | [HeaderExtensionUris#RTP_STREAM_ID], [HeaderExtensionUris#REPAIRED_RTP_STREAM_ID] | RFC 8852 |
/// | [AbsSendTime] | [HeaderExtensionUris#ABS_SEND_TIME] | webrtc.org |
/// | [TransportSequenceNumber] | [HeaderExtensionUris#TRANSPORT_WIDE_CC] | draft-holmer-rmcat-transport-wide-cc-extensions-01 |
/// | [AudioLevel] | [HeaderExtensionUris#AUDIO_LEVEL] | RFC 6464 |
/// | [CsrcAudioLevels] | [HeaderExtensionUris#CSRC_AUDIO_LEVEL] | RFC 6465 |
/// | [TransmissionTimeOffset] | [HeaderExtensionUris#TOFFSET] | RFC 5450 |
/// | [VideoOrientation] | [HeaderExtensionUris#VIDEO_ORIENTATION] | 3GPP TS 26.114 |
/// | [AbsCaptureTime], [PlayoutDelay], [VideoContentType], [VideoTiming], [ColorSpace] | the matching constants | webrtc.org |
/// | [DependencyDescriptor] | [HeaderExtensionUris#DEPENDENCY_DESCRIPTOR] | AV1 RTP payload format, appendix A |
///
/// The raw element bytes of a packet come from `RtpPacket.extension(int)`; [HeaderExtensionMap#find] looks them up by
/// URI, and each value type's `parse` decodes them.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
package com.github.auties00.parley.rtp.extension;
