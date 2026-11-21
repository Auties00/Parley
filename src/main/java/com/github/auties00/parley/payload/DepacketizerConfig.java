package com.github.auties00.parley.payload;

import java.util.Objects;
import java.util.OptionalInt;

/// The settings of a [Depacketizer]: the header extensions it reads, by the ids the session negotiated for them.
///
/// @param audioLevelExtensionId           the id of `urn:ietf:params:rtp-hdrext:ssrc-audio-level`, `1..255`, or an
///                                        empty optional when not negotiated; an audio depacketizer reads the level
///                                        and voice activity of each frame from it
/// @param dependencyDescriptorExtensionId the id of the AV1 dependency descriptor extension, `1..255`, or an empty
///                                        optional when not negotiated; a video depacketizer takes frame boundaries,
///                                        frame numbers and dependencies from it
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
/// @spec https://www.rfc-editor.org/rfc/rfc6464.html RFC 6464: A Real-time Transport Protocol (RTP) Header Extension for Client-to-Mixer Audio Level Indication
/// @spec https://aomediacodec.github.io/av1-rtp-spec/ RTP Payload Format For AV1 (v1.0.0)
public record DepacketizerConfig(OptionalInt audioLevelExtensionId, OptionalInt dependencyDescriptorExtensionId) {
    /// Settings that read no header extension.
    private static final DepacketizerConfig NONE = new DepacketizerConfig(OptionalInt.empty(), OptionalInt.empty());

    /// Creates settings.
    ///
    /// @param audioLevelExtensionId           the audio level extension id
    /// @param dependencyDescriptorExtensionId the dependency descriptor extension id
    /// @throws IllegalArgumentException if an id is outside `1..255`
    public DepacketizerConfig {
        checkId(audioLevelExtensionId);
        checkId(dependencyDescriptorExtensionId);
    }

    /// {@return settings that read no header extension}
    public static DepacketizerConfig none() {
        return NONE;
    }

    /// {@return a copy that reads the audio level from the extension with an id}
    ///
    /// @param id the negotiated id, `1..255`
    /// @throws IllegalArgumentException if `id` is outside `1..255`
    public DepacketizerConfig withAudioLevelExtensionId(int id) {
        return new DepacketizerConfig(OptionalInt.of(id), dependencyDescriptorExtensionId);
    }

    /// {@return a copy that reads the dependency descriptor from the extension with an id}
    ///
    /// @param id the negotiated id, `1..255`
    /// @throws IllegalArgumentException if `id` is outside `1..255`
    public DepacketizerConfig withDependencyDescriptorExtensionId(int id) {
        return new DepacketizerConfig(audioLevelExtensionId, OptionalInt.of(id));
    }

    /// Checks an extension id.
    private static void checkId(OptionalInt id) {
        Objects.requireNonNull(id, "id cannot be null");
        if (id.isPresent() && (id.getAsInt() < 1 || id.getAsInt() > 255)) {
            throw new IllegalArgumentException("header extension id out of range: " + id.getAsInt());
        }
    }
}
