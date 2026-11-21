package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.Codec;

import java.util.List;

/// The codecs and header extensions a connection can negotiate for one media kind, the W3C `RTCRtpCapabilities`.
///
/// Parley does not encode media, so the codecs are those the application declares it can produce and consume: by
/// default every payload format Parley packetizes, narrowed by `PeerConnection.Builder.codecs(...)` or per
/// transceiver by [RtpTransceiver#setCodecPreferences(List)]. Retransmission (`video/rtx`), redundancy (`audio/red`,
/// `video/red`) and forward error correction (`video/ulpfec`, `video/flexfec-03`) appear as codecs too.
///
/// @param codecs           the codecs, in preference order
/// @param headerExtensions the header extensions
/// @spec https://www.w3.org/TR/webrtc/ WebRTC: Real-Time Communication in Browsers
public record RtpCapabilities(List<Codec> codecs, List<RtpHeaderExtensionCapability> headerExtensions) {
    /// Creates the capabilities, copying the lists.
    ///
    /// @param codecs           the codecs
    /// @param headerExtensions the header extensions
    public RtpCapabilities {
        codecs = List.copyOf(codecs);
        headerExtensions = List.copyOf(headerExtensions);
    }
}
