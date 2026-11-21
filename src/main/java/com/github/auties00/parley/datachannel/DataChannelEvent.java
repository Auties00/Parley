package com.github.auties00.parley.datachannel;

import java.io.IOException;
import java.util.Objects;
import java.util.OptionalInt;

/// An event of a [DataChannel], the counterparts of the W3C `RTCDataChannel` events.
///
/// A channel raises [Opened] once, then, in any order, [BufferedAmountLow] whenever its buffered amount falls to its
/// threshold and [Error] when it fails, then [Closing] when either side starts closing it and [Closed] last. A
/// channel that closes before it opens raises only [Closed].
///
/// @spec https://www.w3.org/TR/webrtc/#rtcdatachannel WebRTC: Real-Time Communication in Browsers, RTCDataChannel
public sealed interface DataChannelEvent {
    /// The channel opened (W3C `open`): messages can be sent.
    record Opened() implements DataChannelEvent {
    }

    /// The [buffered amount][DataChannel#bufferedAmount()] fell from above the
    /// [threshold][DataChannel#bufferedAmountLowThreshold()] to at or below it (W3C `bufferedamountlow`).
    record BufferedAmountLow() implements DataChannelEvent {
    }

    /// The channel failed (W3C `error` with an `RTCError` of detail `data-channel-failure` or `sctp-failure`); a
    /// [Closing] or [Closed] follows.
    ///
    /// @param cause          the failure, such as a [DataChannelReceiveOverflowException] when the application did
    ///                       not take received messages fast enough
    /// @param sctpCauseCode  the SCTP cause code (RFC 9260 section 3.3.10) when the failure came with one
    /// @spec https://www.rfc-editor.org/rfc/rfc9260.html RFC 9260: Stream Control Transmission Protocol
    record Error(IOException cause, OptionalInt sctpCauseCode) implements DataChannelEvent {
        /// Creates the event.
        ///
        /// @param cause         the failure
        /// @param sctpCauseCode the SCTP cause code, if any
        public Error {
            Objects.requireNonNull(cause, "cause cannot be null");
            Objects.requireNonNull(sctpCauseCode, "sctpCauseCode cannot be null");
        }
    }

    /// The channel started closing (W3C `closing`): it accepts no more sends.
    record Closing() implements DataChannelEvent {
    }

    /// The channel closed (W3C `close`); the last event.
    record Closed() implements DataChannelEvent {
    }
}
