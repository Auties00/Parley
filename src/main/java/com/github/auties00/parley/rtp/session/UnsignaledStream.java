package com.github.auties00.parley.rtp.session;

import java.util.Objects;
import java.util.Optional;

/// An incoming RTP stream that no receive stream claims: its SSRC is neither signaled nor learned, and its MID, RID
/// or payload type does not lead to a single receive stream.
///
/// The session reports each such SSRC to its unhandled-stream listener, which may create a receive stream for it (an
/// SFU learning a simulcast layer, a peer that sent media before its answer arrived); the packet that triggered the
/// report is routed again once the listener returns.
///
/// @param ssrc        the SSRC of the packet
/// @param payloadType the payload type of the packet
/// @param mid         the MID header extension value, if the packet carried one
/// @param rid         the RID header extension value, if the packet carried one
/// @param repairedRid the repaired RID header extension value, if the packet carried one (an RTX stream)
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public record UnsignaledStream(long ssrc, int payloadType, Optional<String> mid, Optional<String> rid,
                               Optional<String> repairedRid) {
    /// Checks the optional fields are not `null`.
    public UnsignaledStream {
        Objects.requireNonNull(mid, "mid cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        Objects.requireNonNull(repairedRid, "repairedRid cannot be null");
    }
}
