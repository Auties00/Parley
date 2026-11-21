package com.github.auties00.parley.media;

import java.util.List;
import java.util.OptionalLong;

/// What Parley knows about an encoded frame beyond its bytes, per payload format.
///
/// On the send side the application fills the metadata its encoder knows (the temporal layer of a VP8 frame, the
/// picture id of a VP9 frame), and the packetizer writes it into the payload descriptor, generating whatever the
/// application leaves empty. On the receive side the depacketizer reads it back from the descriptor, and the video
/// frame assembler adds the frame id and dependencies it resolved.
///
/// Video metadata shares a vocabulary: a frame id names a frame within its stream (an unwrapped picture id, frame
/// number or arrival counter, increasing in decode order), and the dependencies are the frame ids of the frames it
/// references, empty for a keyframe and for a frame whose references are unknown.
///
/// {@snippet lang = java :
/// switch (frame.metadata()) {
///     case AudioFrameMetadata audio -> mixer.level(audio.audioLevelDbov());
///     case Vp8FrameMetadata vp8 -> log(vp8.temporalId());
///     default -> {}
/// }
/// }
public sealed interface FrameMetadata permits AudioFrameMetadata, Vp8FrameMetadata, Vp9FrameMetadata,
        H264FrameMetadata, H265FrameMetadata, Av1FrameMetadata, GenericFrameMetadata {
    /// {@return the kind of media the metadata describes}
    MediaKind kind();

    /// {@return the frame id the receiver assigned, or an empty optional on the send side and for audio}
    OptionalLong frameId();

    /// {@return the frame ids the frame references, unmodifiable; empty for a keyframe, for a frame whose references
    /// are unknown, and for audio}
    List<Long> dependencies();

    /// {@return a copy with a frame id and the frame ids it references; audio metadata, which has no references,
    /// returns itself}
    ///
    /// @param frameId      the frame id, non-negative
    /// @param dependencies the referenced frame ids, each below `frameId`
    /// @throws IllegalArgumentException if a dependency is negative or not below `frameId`
    FrameMetadata withDependencies(long frameId, List<Long> dependencies);
}
