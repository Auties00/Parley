package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.Codec;
import com.github.auties00.parley.media.EncodedFrame;
import com.github.auties00.parley.media.MediaKind;

import java.nio.ByteBuffer;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/// The `telephone-event` payload format of RFC 4733: DTMF digits and other telephony events, sent at the clock rate
/// of the audio codec they accompany.
///
/// A frame of this format is one payload: one or more [TelephoneEvent] blocks. The packetizer sets the marker bit on
/// the first packet of each event, recognised by its new RTP timestamp; [DtmfToneSequence] produces the frames of a
/// tone string with the timing browsers use.
///
/// @param codec the codec, `audio/telephone-event`
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public record TelephoneEventFormat(Codec codec) implements PayloadFormat {
    /// Creates the format.
    ///
    /// @param codec the codec
    /// @throws IllegalArgumentException if the codec is not `audio/telephone-event`
    public TelephoneEventFormat {
        Objects.requireNonNull(codec, "codec cannot be null");
        if (!codec.mimeType().equalsIgnoreCase("audio/telephone-event")) {
            throw new IllegalArgumentException("not audio/telephone-event: " + codec);
        }
    }

    /// {@return the event codes the codec declares, from its format parameter list such as `0-15,66`; the DTMF events
    /// `0-15` when the list is absent or malformed}
    public BitSet events() {
        var result = new BitSet(256);
        var list = codec.formatParameter("");
        if (list.isEmpty()) {
            result.set(0, 16);
            return result;
        }
        try {
            for (var part : list.get().split(",")) {
                var range = part.strip();
                var dash = range.indexOf('-');
                var low = Integer.parseInt(dash < 0 ? range : range.substring(0, dash).strip());
                var high = dash < 0 ? low : Integer.parseInt(range.substring(dash + 1).strip());
                if (low < 0 || high > 255 || low > high) {
                    throw new NumberFormatException(range);
                }
                result.set(low, high + 1);
            }
        } catch (NumberFormatException exception) {
            result.clear();
            result.set(0, 16);
        }
        return result;
    }

    @Override
    public Packetizer packetizer(PacketizerConfig config) {
        Objects.requireNonNull(config, "config cannot be null");
        return new Packetizer() {
            /// The RTP timestamp of the previous frame, or `-1` before the first.
            private long previousTimestamp = -1;

            @Override
            public List<PacketizedPayload> packetize(EncodedFrame frame) {
                Payloads.checkKind(frame, MediaKind.AUDIO);
                var data = frame.data();
                if (!valid(data) || data.remaining() > config.maxPayloadSize()) {
                    throw new IllegalArgumentException("not a telephone-event payload of whole blocks");
                }
                var marker = frame.rtpTimestamp() != previousTimestamp;
                previousTimestamp = frame.rtpTimestamp();
                return List.of(PacketizedPayload.of(data, marker));
            }
        };
    }

    @Override
    public Depacketizer depacketizer(DepacketizerConfig config) {
        return new AudioDepacketizer(TelephoneEventFormat::valid, Objects.requireNonNull(config, "config cannot be null"));
    }

    /// {@return `true`: every event block stands alone}
    ///
    /// @param payload the payload
    @Override
    public boolean isKeyframe(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return true;
    }

    /// {@return an empty optional: every packet of an event repeats the event's start timestamp, so a payload spans no
    /// timestamp range of its own}
    ///
    /// @param payload the payload
    @Override
    public OptionalInt timestampDuration(ByteBuffer payload) {
        Objects.requireNonNull(payload, "payload cannot be null");
        return OptionalInt.empty();
    }

    /// {@return whether a payload is a whole, non-zero number of event blocks}
    private static boolean valid(ByteBuffer payload) {
        return payload.hasRemaining() && payload.remaining() % TelephoneEvent.SIZE == 0;
    }
}
