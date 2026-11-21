package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.rtp.RtpPacket;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/// The sending side of a sender, which a [LocalTrack] writes its frames and forwarded packets into.
interface FrameSink {
    /// A packet a [LocalForwardedTrack] forwards.
    ///
    /// @param packet       the packet; the sink reads it and does not keep it
    /// @param rid          the layer to send it on, or an empty optional for the first one
    /// @param codec        the codec of its payload type, or an empty optional when the payload type is already in
    ///                     the sender's numbering
    /// @param extensions   the extension ids of the packet mapped to their URIs, or an empty optional when the ids
    ///                     are already in the sender's numbering
    record Forwarded(RtpPacket packet, Optional<String> rid, Optional<Codec> codec,
                     Optional<Map<Integer, URI>> extensions) {
        public Forwarded {
            Objects.requireNonNull(packet);
            Objects.requireNonNull(rid);
            Objects.requireNonNull(codec);
            Objects.requireNonNull(extensions);
        }
    }

    /// Sends a frame on the encoding named `rid`, or on the first encoding when `rid` is empty; never throws for a
    /// network failure, which the sender counts.
    ///
    /// @return whether the frame was taken: `false` when the sender is not negotiated, not sending, has no such
    ///         layer or the layer is inactive
    boolean accept(EncodedFrame frame, Optional<String> rid);

    /// Sends a forwarded packet; never throws for a network failure.
    ///
    /// @return whether the packet was taken, as for [#accept(EncodedFrame, Optional)]
    boolean forward(Forwarded packet);

    /// {@return whether the sink currently sends what it is given}
    boolean isSending();
}
