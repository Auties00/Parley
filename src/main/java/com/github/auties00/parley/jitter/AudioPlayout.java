package com.github.auties00.parley.jitter;

import com.github.auties00.parley.media.EncodedFrame;

import java.time.Duration;
import java.util.Objects;

/// What an [AudioPlayoutBuffer] has for one playout instant: a frame to decode, a gap to conceal, or silence.
///
/// {@snippet lang = java :
/// while (running) {
///     switch (buffer.next()) {
///         case AudioPlayout.Frame(var frame) -> speaker.play(decoder.decode(frame.data()));
///         case AudioPlayout.Missing(var timestamp, var duration) -> speaker.play(decoder.conceal(duration));
///         case AudioPlayout.Silence(var duration) -> speaker.play(comfortNoise(duration));
///     }
/// }
/// }
public sealed interface AudioPlayout {
    /// {@return how much audio this outcome stands for}
    Duration duration();

    /// A frame that arrived in time, to decode and play now.
    ///
    /// @param frame    the frame
    /// @param duration the duration of its audio
    record Frame(EncodedFrame frame, Duration duration) implements AudioPlayout {
        /// Creates the outcome.
        ///
        /// @param frame    the frame
        /// @param duration the duration, positive
        /// @throws IllegalArgumentException if `duration` is not positive
        public Frame {
            Objects.requireNonNull(frame, "frame cannot be null");
            checkPositive(duration);
        }
    }

    /// A frame that did not arrive in time (lost or late), for the decoder to conceal: packet loss concealment, or a
    /// frame stretched to grow the buffer's delay.
    ///
    /// @param rtpTimestamp the RTP timestamp the missing audio would have had
    /// @param duration     the duration to conceal
    record Missing(long rtpTimestamp, Duration duration) implements AudioPlayout {
        /// Creates the outcome.
        ///
        /// @param rtpTimestamp the RTP timestamp
        /// @param duration     the duration, positive
        /// @throws IllegalArgumentException if `duration` is not positive or `rtpTimestamp` is outside the unsigned
        ///                                  32-bit range
        public Missing {
            if (rtpTimestamp < 0 || rtpTimestamp > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("RTP timestamp out of range: " + rtpTimestamp);
            }
            checkPositive(duration);
        }
    }

    /// A stretch during which the sender is silent on purpose (discontinuous transmission or comfort noise), to fill
    /// with silence or comfort noise rather than concealment.
    ///
    /// @param duration the duration of the silence
    record Silence(Duration duration) implements AudioPlayout {
        /// Creates the outcome.
        ///
        /// @param duration the duration, positive
        /// @throws IllegalArgumentException if `duration` is not positive
        public Silence {
            checkPositive(duration);
        }
    }

    /// Checks that a duration is positive.
    private static void checkPositive(Duration duration) {
        Objects.requireNonNull(duration, "duration cannot be null");
        if (!duration.isPositive()) {
            throw new IllegalArgumentException("duration must be positive: " + duration);
        }
    }
}
