package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;

import java.util.Objects;
import java.util.Optional;

/// A local track that forwards RTP packets received from another peer without decoding them, the building block of
/// an SFU: the packets of a [RemoteTrack] in [RemoteTrackMode#RAW_PACKETS] mode go out on every sender this track is
/// attached to.
///
/// Each sender keeps its own RTP stream: the packet's payload is sent unchanged, while its SSRC, sequence number and
/// timestamp are rewritten into the sender's spaces (continuous when the forwarded source changes, as on a simulcast
/// layer switch), its payload type is mapped to the type the sender negotiated for the same codec (name, clock
/// rate, channels and profile), and its header extensions are renumbered to the sender's ids by URI; extensions the
/// sender did not negotiate are dropped, and the sender adds its own transport-wide sequence numbers and send times.
/// A packet whose codec the sender did not negotiate is dropped. Retransmission, FEC and pacing are the sender's.
///
/// {@snippet lang = java :
/// var forwarded = LocalTrack.forwarded("relay-" + remote.id(), remote.kind());
/// subscriber.addTrack(forwarded, "stream-1");
/// try (var packets = remote.packets()) {
///     for (var packet : packets) {
///         if (packet.rid().equals(selectedLayer)) {
///             forwarded.write(packet);
///         }
///     }
/// }
/// }
///
/// A packet written while no sender is negotiated is dropped and counted in [#framesDropped()]. When the subscriber
/// needs a key frame (it joined, or the forwarded layer changes), the track raises
/// [LocalTrackEvent.KeyframeRequested]; the SFU passes it on with [RtpReceiver#requestKeyFrame()].
///
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html RFC 7667: RTP Topologies
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public final class LocalForwardedTrack extends LocalTrack {
    /// Creates the track.
    LocalForwardedTrack(String id, MediaKind kind) {
        super(id, kind);
    }

    /// Forwards a packet received by a [RemoteTrack], mapping its payload type and header extensions by the codec
    /// and extension map it carries.
    ///
    /// On a simulcast sender, the packet's RTP stream id selects the layer it goes out on; a packet without one, or
    /// whose layer the sender lacks, goes to the first layer.
    ///
    /// @param packet the packet; the track reads it and does not keep it
    /// @throws IllegalStateException if the track has ended
    public void write(RemoteTrack.Packet packet) {
        Objects.requireNonNull(packet, "packet cannot be null");
        forward(new FrameSink.Forwarded(packet.packet(), packet.rid(), packet.codec(),
                Optional.of(packet.extensions())));
    }

    /// Forwards a packet whose payload type and header extension ids are already those the senders negotiated, as
    /// when the application built it.
    ///
    /// @param packet the packet; the track reads it and does not keep it
    /// @param rid    the layer to send it on, or an empty optional for the first one
    /// @throws IllegalStateException if the track has ended
    public void write(RtpPacket packet, Optional<String> rid) {
        Objects.requireNonNull(packet, "packet cannot be null");
        Objects.requireNonNull(rid, "rid cannot be null");
        forward(new FrameSink.Forwarded(packet, rid, Optional.empty(), Optional.empty()));
    }
}
