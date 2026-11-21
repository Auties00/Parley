package com.github.auties00.parley.cc;

import java.util.List;

/// Supplies the packets a [Pacer] sends when it must put more bytes on the wire than the media queue holds: to
/// complete a probe, or to keep up a padding rate.
///
/// @implSpec An implementation should prefer RTX retransmissions of recently sent media packets (RFC 4588 payload
/// padding), which may help the receiver, over padding-only packets, and fall back to padding-only RTP packets
/// (RFC 3550 section 5.1, padding bit set) on the RTX stream. It is called on the pacer's thread and must not block
/// on the network; it returns an empty list when it can produce nothing, and the pacer then stops asking until the
/// next padding interval.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
@FunctionalInterface
public interface PaddingSource {
    /// Produces padding packets totalling about `targetBytes`.
    ///
    /// @param targetBytes the number of bytes wanted, positive; the packets may total somewhat more or less
    /// @return the packets to send, in order; empty when none can be produced
    List<PaddingPacket> generatePadding(int targetBytes);
}
