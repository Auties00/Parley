package com.github.auties00.parley.payload;

import com.github.auties00.parley.media.EncodedFrame;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/// Turns the stream of telephone-event frames a receiver gets into one report per event.
///
/// A sender repeats each event in many packets and its final packet three times; the detector reports an event once,
/// when its first final packet arrives. An event whose final packets are all lost is reported when the next event
/// starts, with the last duration seen. Duplicates and packets of already reported events are ignored. Long events
/// split into segments (consecutive timestamps one 16-bit duration apart) are reported per segment.
///
/// A detector is not safe for concurrent use.
///
/// @spec https://www.rfc-editor.org/rfc/rfc4733.html RFC 4733: RTP Payload for DTMF Digits, Telephony Tones, and Telephony Signals
public final class TelephoneEventDetector {
    /// The timestamp of the event in progress, or `-1` when none is.
    private long currentTimestamp = -1;

    /// The last block of the event in progress.
    private TelephoneEvent currentEvent;

    /// The timestamp of the last event reported, or `-1`.
    private long reportedTimestamp = -1;

    /// Creates a detector.
    public TelephoneEventDetector() {
    }

    /// Feeds one telephone-event frame, as a [TelephoneEventFormat] depacketizer assembles it.
    ///
    /// @param frame the frame
    /// @return the events this frame completes, in order: none, the event in progress, or an event whose end was lost
    ///         followed by this one
    /// @throws PayloadFormatException if the frame is not a whole number of event blocks
    public List<DetectedEvent> accept(EncodedFrame frame) throws PayloadFormatException {
        Objects.requireNonNull(frame, "frame cannot be null");
        var timestamp = frame.rtpTimestamp();
        var events = TelephoneEvent.parseAll(frame.data());
        var event = events.getLast();
        var result = new ArrayList<DetectedEvent>(2);
        if (timestamp == reportedTimestamp) {
            return List.of();
        }
        if (currentTimestamp >= 0 && currentTimestamp != timestamp) {
            if (isOlder(timestamp, currentTimestamp)) {
                return List.of();
            }
            result.add(DetectedEvent.of(currentTimestamp, currentEvent));
            reportedTimestamp = currentTimestamp;
            currentTimestamp = -1;
        }
        if (event.end()) {
            result.add(DetectedEvent.of(timestamp, event));
            reportedTimestamp = timestamp;
            currentTimestamp = -1;
            currentEvent = null;
        } else {
            currentTimestamp = timestamp;
            currentEvent = event;
        }
        return List.copyOf(result);
    }

    /// {@return whether one 32-bit timestamp precedes another, with wrap-around}
    private static boolean isOlder(long timestamp, long than) {
        return ((than - timestamp) & 0xFFFFFFFFL) < 0x80000000L;
    }

    /// One telephone event as the receiver detected it.
    ///
    /// @param event        the event code, `0..255`
    /// @param symbol       the DTMF character, for events `0..15`
    /// @param rtpTimestamp the RTP timestamp of the event's start
    /// @param duration     the event's duration in clock units
    /// @param volume       the event's volume in -dBm0
    /// @param ended        whether the sender's final packet arrived; `false` when the event was closed by the start
    ///                     of the next one
    public record DetectedEvent(int event, Optional<Character> symbol, long rtpTimestamp, int duration, int volume,
                                boolean ended) {
        /// Creates a detected event.
        ///
        /// @param event        the event code
        /// @param symbol       the character
        /// @param rtpTimestamp the timestamp
        /// @param duration     the duration
        /// @param volume       the volume
        /// @param ended        whether the final packet arrived
        public DetectedEvent {
            Objects.requireNonNull(symbol, "symbol cannot be null");
        }

        /// {@return the detected form of the last block of an event}
        static DetectedEvent of(long timestamp, TelephoneEvent block) {
            return new DetectedEvent(block.event(), block.symbol(), timestamp, block.duration(), block.volume(),
                    block.end());
        }
    }
}
