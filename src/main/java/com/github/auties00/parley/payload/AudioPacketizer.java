package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.AudioFrameMetadata;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;
import com.github.auties00.parley.rtp.extension.HeaderExtensionUris;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

/// The packetizer of the audio formats, one frame per payload.
///
/// The marker bit goes on the first packet of each talkspurt: the first frame, and every frame whose timestamp does
/// not follow the previous frame's (the sender stopped sending during silence). A frame whose metadata has a level
/// gets an `ssrc-audio-level` value.
final class AudioPacketizer implements Packetizer {
    /// The format, for the duration of each payload.
    private final PayloadFormat format;

    /// The largest payload.
    private final int maxPayloadSize;

    /// The timestamp the next frame has when it follows the previous one, or `-1` when unknown.
    private long expectedTimestamp = -1;

    /// Whether a frame was packetized.
    private boolean started;

    /// Creates a packetizer.
    AudioPacketizer(PayloadFormat format, PacketizerConfig config) {
        this.format = format;
        this.maxPayloadSize = config.maxPayloadSize();
    }

    @Override
    public List<PacketizedPayload> packetize(EncodedFrame frame) {
        Payloads.checkKind(frame, MediaKind.AUDIO);
        var data = frame.data();
        if (data.remaining() > maxPayloadSize) {
            throw new IllegalArgumentException("audio frame of " + data.remaining() + " bytes exceeds the payload size "
                    + maxPayloadSize);
        }
        var marker = !started || expectedTimestamp >= 0 && expectedTimestamp != frame.rtpTimestamp();
        started = true;
        var duration = format.timestampDuration(data);
        expectedTimestamp = duration.isPresent() ? (frame.rtpTimestamp() + duration.getAsInt()) & 0xFFFFFFFFL : -1;
        Map<URI, ByteBuffer> extensions = Map.of();
        if (frame.metadata() instanceof AudioFrameMetadata(var level, var voice, var ignored) && level.isPresent()) {
            var value = ByteBuffer.allocate(1).put(0, (byte) ((voice ? 0x80 : 0) | level.getAsInt()));
            extensions = Map.of(HeaderExtensionUris.AUDIO_LEVEL, value);
        }
        return List.of(new PacketizedPayload(data, marker, extensions));
    }
}
