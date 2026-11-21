package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The metadata of an audio frame: its level and voice activity, as the `ssrc-audio-level` header extension carries
/// them, and the contributing sources of a mixed frame.
///
/// @param audioLevelDbov      the level of the audio in -dBov, `0` (loudest) to `127` (silence), or an empty optional
///                            when unknown
/// @param voiceActivity       whether the frame contains voice, as the sender's voice activity detector decided;
///                            `false` when unknown
/// @param contributingSources the CSRCs of a frame a mixer produced, unmodifiable, each an unsigned 32-bit value
/// @spec https://www.rfc-editor.org/rfc/rfc6464.html RFC 6464: A Real-time Transport Protocol (RTP) Header Extension for Client-to-Mixer Audio Level Indication
public record AudioFrameMetadata(OptionalInt audioLevelDbov, boolean voiceActivity, List<Long> contributingSources)
        implements FrameMetadata {
    /// Metadata that knows nothing about the frame.
    private static final AudioFrameMetadata NONE = new AudioFrameMetadata(OptionalInt.empty(), false, List.of());

    /// Creates audio metadata.
    ///
    /// @param audioLevelDbov      the level
    /// @param voiceActivity       the voice activity flag
    /// @param contributingSources the contributing sources, copied
    /// @throws IllegalArgumentException if the level is outside `0..127`, a source is outside the unsigned 32-bit
    ///                                  range, or there are more than fifteen sources
    public AudioFrameMetadata {
        Objects.requireNonNull(audioLevelDbov, "audioLevelDbov cannot be null");
        if (audioLevelDbov.isPresent() && (audioLevelDbov.getAsInt() < 0 || audioLevelDbov.getAsInt() > 127)) {
            throw new IllegalArgumentException("audio level out of range: " + audioLevelDbov.getAsInt());
        }
        contributingSources = List.copyOf(contributingSources);
        if (contributingSources.size() > 15) {
            throw new IllegalArgumentException("at most 15 contributing sources");
        }
        for (var source : contributingSources) {
            if (source < 0 || source > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("contributing source out of range: " + source);
            }
        }
    }

    /// {@return metadata with no level, no voice activity and no contributing sources}
    public static AudioFrameMetadata none() {
        return NONE;
    }

    /// {@return metadata with a level and a voice activity flag}
    ///
    /// @param audioLevelDbov the level in -dBov, `0..127`
    /// @param voiceActivity  whether the frame contains voice
    /// @throws IllegalArgumentException if the level is outside `0..127`
    public static AudioFrameMetadata ofLevel(int audioLevelDbov, boolean voiceActivity) {
        return new AudioFrameMetadata(OptionalInt.of(audioLevelDbov), voiceActivity, List.of());
    }

    /// {@return [MediaKind#AUDIO]}
    @Override
    public MediaKind kind() {
        return MediaKind.AUDIO;
    }

    /// {@return an empty optional: audio frames have no frame ids}
    @Override
    public OptionalLong frameId() {
        return OptionalLong.empty();
    }

    /// {@return an empty list: audio frames reference no other frame}
    @Override
    public List<Long> dependencies() {
        return List.of();
    }

    /// {@return this metadata, since audio frames have no references}
    ///
    /// @param frameId      ignored
    /// @param dependencies ignored
    @Override
    public AudioFrameMetadata withDependencies(long frameId, List<Long> dependencies) {
        Objects.requireNonNull(dependencies, "dependencies cannot be null");
        return this;
    }
}
