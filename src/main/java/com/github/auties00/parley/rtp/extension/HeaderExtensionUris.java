package com.github.auties00.parley.rtp.extension;

import java.net.URI;

/// The URIs of the RTP header extensions Parley understands, as `a=extmap` lines name them.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc8852.html RFC 8852: RTP Stream Identifier Source Description (SDES)
/// @spec https://www.rfc-editor.org/rfc/rfc6464.html RFC 6464: A Real-time Transport Protocol (RTP) Header Extension for Client-to-Mixer Audio Level Indication
/// @spec https://www.rfc-editor.org/rfc/rfc6465.html RFC 6465: A Real-time Transport Protocol (RTP) Header Extension for Mixer-to-Client Audio Level Indication
/// @spec https://www.rfc-editor.org/rfc/rfc5450.html RFC 5450: Transmission Time Offsets in RTP Streams
public final class HeaderExtensionUris {
    /// The media identification, [Mid].
    public static final URI MID = URI.create("urn:ietf:params:rtp-hdrext:sdes:mid");
    /// The RTP stream identifier, [RtpStreamId].
    public static final URI RTP_STREAM_ID = URI.create("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id");
    /// The repaired RTP stream identifier, [RepairedRtpStreamId].
    public static final URI REPAIRED_RTP_STREAM_ID =
            URI.create("urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id");
    /// The absolute send time, [AbsSendTime].
    public static final URI ABS_SEND_TIME = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
    /// The transport-wide sequence number, [TransportSequenceNumber].
    public static final URI TRANSPORT_WIDE_CC =
            URI.create("http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
    /// The client-to-mixer audio level, [AudioLevel].
    public static final URI AUDIO_LEVEL = URI.create("urn:ietf:params:rtp-hdrext:ssrc-audio-level");
    /// The mixer-to-client audio levels, [CsrcAudioLevels].
    public static final URI CSRC_AUDIO_LEVEL = URI.create("urn:ietf:params:rtp-hdrext:csrc-audio-level");
    /// The transmission time offset, [TransmissionTimeOffset].
    public static final URI TOFFSET = URI.create("urn:ietf:params:rtp-hdrext:toffset");
    /// The coordination of video orientation, [VideoOrientation].
    public static final URI VIDEO_ORIENTATION = URI.create("urn:3gpp:video-orientation");
    /// The absolute capture time, [AbsCaptureTime].
    public static final URI ABS_CAPTURE_TIME =
            URI.create("http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
    /// The playout delay limits, [PlayoutDelay].
    public static final URI PLAYOUT_DELAY = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/playout-delay");
    /// The video content type, [VideoContentType].
    public static final URI VIDEO_CONTENT_TYPE =
            URI.create("http://www.webrtc.org/experiments/rtp-hdrext/video-content-type");
    /// The video timing, [VideoTiming].
    public static final URI VIDEO_TIMING = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/video-timing");
    /// The color space, [ColorSpace].
    public static final URI COLOR_SPACE = URI.create("http://www.webrtc.org/experiments/rtp-hdrext/color-space");
    /// The AV1 dependency descriptor, [DependencyDescriptor].
    public static final URI DEPENDENCY_DESCRIPTOR = URI.create(
            "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension");

    private HeaderExtensionUris() {
        throw new AssertionError("HeaderExtensionUris cannot be instantiated");
    }
}
