package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.util.Objects;
import java.util.Optional;

/// A local video track: the application writes encoded video frames into it, one stream of frames per simulcast
/// layer when its sender has several encodings.
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
/// @spec https://www.rfc-editor.org/rfc/rfc8853.html RFC 8853: Using Simulcast in Session Description Protocol (SDP) and RTP Sessions
public final class LocalVideoTrack extends LocalTrack {
    /// Creates the track.
    LocalVideoTrack(String id) {
        super(id, MediaKind.VIDEO);
    }

    /// Writes one encoded frame to the simulcast layer named `rid` of every sender the track is attached to.
    ///
    /// A sender without a layer of that name drops the frame.
    ///
    /// @param frame the frame
    /// @param rid   the RTP stream id of the layer
    /// @throws IllegalArgumentException if the frame is not a video frame
    /// @throws IllegalStateException    if the track has ended
    public void write(EncodedFrame frame, String rid) {
        write(frame, Optional.of(Objects.requireNonNull(rid, "rid cannot be null")));
    }
}
