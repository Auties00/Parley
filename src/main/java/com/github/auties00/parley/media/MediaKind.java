package com.github.auties00.parley.media;

import java.util.Locale;
import java.util.Optional;

/// The kind of a media track, the top-level type of its codecs' media types.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
public enum MediaKind {
    /// Audio, media type `audio/*`.
    AUDIO("audio"),

    /// Video, media type `video/*`.
    VIDEO("video");

    /// The top-level media type.
    private final String type;

    MediaKind(String type) {
        this.type = type;
    }

    /// {@return the top-level media type, `audio` or `video`, also the SDP media name of the kind}
    public String type() {
        return type;
    }

    /// {@return the kind whose top-level media type is `type`, ignoring case, or an empty optional for any other
    /// type}
    ///
    /// @param type a top-level media type, such as `audio`
    public static Optional<MediaKind> ofType(String type) {
        return switch (type.toLowerCase(Locale.ROOT)) {
            case "audio" -> Optional.of(AUDIO);
            case "video" -> Optional.of(VIDEO);
            default -> Optional.empty();
        };
    }
}
