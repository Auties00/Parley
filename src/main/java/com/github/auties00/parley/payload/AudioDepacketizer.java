package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Predicate;

/// The depacketizer of the audio formats, one frame per payload.
///
/// The frame's metadata carries the contributing sources of the packet and, when the `ssrc-audio-level` extension
/// is negotiated, the level and voice activity flag of its one-byte value.
final class AudioDepacketizer implements Depacketizer {
    /// The test a payload must pass to be valid.
    private final Predicate<ByteBuffer> validity;

    /// The negotiated id of the audio level extension.
    private final OptionalInt audioLevelId;

    /// Creates a depacketizer.
    AudioDepacketizer(Predicate<ByteBuffer> validity, DepacketizerConfig config) {
        this.validity = validity;
        this.audioLevelId = config.audioLevelExtensionId();
    }

    @Override
    public PacketBoundaries inspect(RtpPacket packet) {
        return validity.test(packet.payload()) ? PacketBoundaries.singlePacket(true) : PacketBoundaries.invalid();
    }

    @Override
    public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
        Payloads.checkRun(packetsOfOneFrame);
        if (packetsOfOneFrame.size() != 1) {
            throw new PayloadFormatException("an audio frame is one packet, got " + packetsOfOneFrame.size());
        }
        var packet = packetsOfOneFrame.getFirst();
        var payload = packet.payload();
        if (!validity.test(payload)) {
            throw new PayloadFormatException("malformed audio payload");
        }
        var level = OptionalInt.empty();
        var voice = false;
        if (audioLevelId.isPresent()) {
            var value = packet.extension(audioLevelId.getAsInt());
            if (value.isPresent() && value.get().hasRemaining()) {
                var b = value.get().get(value.get().position()) & 0xFF;
                level = OptionalInt.of(b & 0x7F);
                voice = (b & 0x80) != 0;
            }
        }
        var metadata = new AudioFrameMetadata(level, voice, packet.csrcs());
        return new EncodedFrame(MediaKind.AUDIO, Payloads.copy(payload), packet.timestamp(), true, Optional.empty(),
                metadata);
    }
}
