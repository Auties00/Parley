package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpFormatException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// The audio level of each contributing source a mixer mixed into the packet, in the order of the packet's CSRC
/// list.
///
/// @param levels the levels in `-dBov`, `0..127` each, `1..15` of them
/// @spec https://www.rfc-editor.org/rfc/rfc6465.html RFC 6465: A Real-time Transport Protocol (RTP) Header Extension for Mixer-to-Client Audio Level Indication
public record CsrcAudioLevels(List<Integer> levels) implements HeaderExtension {
    /// Validates and copies `levels`.
    ///
    /// @throws IllegalArgumentException if there are not `1..15` levels or one is out of range
    public CsrcAudioLevels {
        levels = List.copyOf(Objects.requireNonNull(levels, "levels cannot be null"));
        if (levels.isEmpty() || levels.size() > 15) {
            throw new IllegalArgumentException("1..15 levels required: " + levels.size());
        }
        for (var level : levels) {
            if (level < 0 || level > 127) {
                throw new IllegalArgumentException("level must be in 0..127: " + level);
            }
        }
    }

    /// Parses an element value: one level per byte, the reserved high bit ignored.
    ///
    /// @param value the element value; the position is advanced past the levels read
    /// @return the levels
    /// @throws RtpFormatException if the value is empty
    public static CsrcAudioLevels parse(ByteBuffer value) throws RtpFormatException {
        ExtensionCodec.require(value, 1, "csrc-audio-level");
        var levels = new ArrayList<Integer>();
        while (value.hasRemaining() && levels.size() < 15) {
            levels.add(value.get() & 0x7F);
        }
        return new CsrcAudioLevels(levels);
    }

    @Override
    public URI uri() {
        return HeaderExtensionUris.CSRC_AUDIO_LEVEL;
    }

    @Override
    public int encodedLength() {
        return levels.size();
    }

    @Override
    public void writeTo(ByteBuffer destination) {
        ExtensionCodec.checkRoom(destination, levels.size());
        for (var level : levels) {
            destination.put((byte) (int) level);
        }
    }
}
