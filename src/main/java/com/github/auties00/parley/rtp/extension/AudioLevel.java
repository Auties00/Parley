package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;

/// The audio level of the packet's audio, as the client measured it, and whether it holds voice.
///
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |V|    level    |
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// @param voiceActivity whether the sender's voice activity detector flagged the audio as speech
/// @param level         the level in `-dBov`, `0..127`: `0` is the loudest, `127` silence
/// @spec https://www.rfc-editor.org/rfc/rfc6464.html RFC 6464: A Real-time Transport Protocol (RTP) Header Extension for Client-to-Mixer Audio Level Indication
public record AudioLevel(boolean voiceActivity, int level) implements HeaderExtension {
    /// Validates the range.
    ///
    /// @throws IllegalArgumentException if `level` is out of range
    public AudioLevel {
        if (level < 0 || level > 127) {
            throw new IllegalArgumentException("level must be in 0..127: " + level);
        }
    }

    /// Parses an element value; padding after the first byte is ignored.
    ///
    /// @param value the element value; the position is advanced past the byte read
    /// @return the level
    /// @throws RtpFormatException if the value is empty
    public static AudioLevel parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 1, "ssrc-audio-level");
        var b = value.get() & 0xFF;
        return new AudioLevel((b & 0x80) != 0, b & 0x7F);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.AUDIO_LEVEL;
    }

    @Override
    public int encodedLength() {
        return 1;
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, 1);
        destination.put((byte) ((voiceActivity ? 0x80 : 0) | level));
    }
}
