package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.GenericFrameMetadata;
import com.github.auties00.parley.rtp.RtpPacket;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/// The passthrough payload format of a codec Parley does not interpret: a frame's bytes are split into payloads of
/// at most the configured size with no payload header, and the marker bit ends a frame.
///
/// Since the payload says nothing, a frame's start is known only from the end of the previous one, and its
/// keyframe flag is `false`; a negotiated dependency descriptor (see [DepacketizerConfig]) supplies the boundaries,
/// frame ids and dependencies a receiver needs.
///
/// @param codec the codec
public record GenericFormat(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec any codec
    public GenericFormat {
        Objects.requireNonNull(codec, "codec cannot be null");
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        return frame -> {
            Payloads.checkKind(frame, codec.kind());
            var data = frame.data();
            if (!data.hasRemaining()) {
                throw new IllegalArgumentException("empty frame");
            }
            var fragments = Payloads.split(data, config.maxPayloadSize());
            var result = new ArrayList<PacketizedPayload>(fragments.size());
            for (var k = 0; k < fragments.size(); k++) {
                result.add(PacketizedPayload.of(fragments.get(k), k == fragments.size() - 1));
            }
            return List.copyOf(result);
        };
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        var kind = codec.kind();
        Depacketizer passthrough = new Depacketizer() {
            @Override
            public PacketBoundaries inspect(RtpPacket packet) {
                return packet.payload().hasRemaining()
                        ? new PacketBoundaries(true, false, packet.marker(), false, false, 0, 0)
                        : PacketBoundaries.invalid();
            }

            @Override
            public EncodedFrame assemble(List<RtpPacket> packetsOfOneFrame) throws PayloadFormatException {
                Payloads.checkRun(packetsOfOneFrame);
                var out = new ByteArrayOutputStream();
                for (var packet : packetsOfOneFrame) {
                    var payload = packet.payload();
                    if (!payload.hasRemaining()) {
                        throw new PayloadFormatException("empty payload");
                    }
                    var bytes = new byte[payload.remaining()];
                    payload.get(payload.position(), bytes);
                    out.writeBytes(bytes);
                }
                return new EncodedFrame(kind, ByteBuffer.wrap(out.toByteArray()),
                        packetsOfOneFrame.getFirst().timestamp(), false, Optional.empty(),
                        GenericFrameMetadata.none(kind));
            }
        };
        return VideoDepacketizer.withDescriptor(passthrough, config);
    }

    /// {@return `false`: an opaque payload does not tell}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return false;
    }

    /// {@return an empty optional: an opaque payload does not tell}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return OptionalInt.empty();
    }
}
