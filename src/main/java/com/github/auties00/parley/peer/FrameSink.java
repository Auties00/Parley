package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;

import java.util.Optional;

/// The sending side of a sender, which a [LocalTrack] writes its frames into.
@FunctionalInterface
interface FrameSink {
    /// Sends a frame on the encoding named `rid`, or on the first encoding when `rid` is empty; never throws for a
    /// network failure, which the sender counts.
    void accept(EncodedFrame frame, Optional<String> rid);
}
