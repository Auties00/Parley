package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.MediaKind;

/// A local audio track: the application writes encoded audio frames, one per packet time, into it.
///
/// A sender of an audio track can also send DTMF tones through its [DtmfSender].
///
/// @spec https://www.w3.org/TR/mediacapture-streams/ Media Capture and Streams
public final class LocalAudioTrack extends LocalTrack {
    /// Creates the track.
    LocalAudioTrack(String id) {
        super(id, MediaKind.AUDIO);
    }
}
