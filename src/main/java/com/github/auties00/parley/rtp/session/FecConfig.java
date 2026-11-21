package com.github.auties00.parley.rtp.session;

import java.util.Objects;

/// Forward error correction for a video stream: ULPFEC carried in RED on the media SSRC, as browsers send it, or
/// FlexFEC on its own SSRC.
///
/// ULPFEC masks are chosen per frame from the loss pattern the peer's NACKs show: masks against random loss
/// (each media packet protected by two FEC packets where the rate allows) while losses come one at a time, and
/// interleaved masks against bursts (consecutive packets protected by different FEC packets) once losses come in
/// runs. A FlexFEC stream follows its [FlexfecScheme].
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public sealed interface FecConfig {
    /// {@return the FEC packets generated per media packet, in percent, `0..100`}
    int protectionPercent();

    /// ULPFEC with RED: every media packet is sent inside RED, and the FEC packets are RED packets whose block
    /// carries the `ulpfec` payload type.
    ///
    /// @param redPayloadType    the payload type negotiated for `red`, `0..127`
    /// @param ulpfecPayloadType the payload type negotiated for `ulpfec`, `0..127`
    /// @param protectionPercent the FEC packets per media packet in percent, `0..100`; a receive stream ignores it
    record Ulpfec(int redPayloadType, int ulpfecPayloadType, int protectionPercent) implements FecConfig {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range
        public Ulpfec {
            SessionChecks.payloadType(redPayloadType, "redPayloadType");
            SessionChecks.payloadType(ulpfecPayloadType, "ulpfecPayloadType");
            SessionChecks.percent(protectionPercent);
        }
    }

    /// FlexFEC on its own SSRC, associated with the media SSRC by `a=ssrc-group:FEC-FR`.
    ///
    /// @param payloadType       the payload type negotiated for `flexfec` or `flexfec-03`, `0..127`
    /// @param ssrc              the FlexFEC SSRC, an unsigned 32-bit value
    /// @param draft03           whether the negotiated format is `flexfec-03`, the header layout browsers send,
    ///                          rather than RFC 8627
    /// @param protectionPercent the FEC packets per media packet in percent, `0..100`, for the mask and
    ///                          retransmission schemes; a receive stream ignores it
    /// @param scheme            how the sender chooses the protected packets; a receive stream recovers from every
    ///                          scheme whatever this says
    record Flexfec(int payloadType, long ssrc, boolean draft03, int protectionPercent, FlexfecScheme scheme)
            implements FecConfig {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is out of range, or a scheme other than [FlexfecScheme.Mask]
        ///                                  is asked of the `flexfec-03` layout, which has no other
        public Flexfec {
            SessionChecks.payloadType(payloadType, "payloadType");
            SessionChecks.ssrc(ssrc, "ssrc");
            SessionChecks.percent(protectionPercent);
            Objects.requireNonNull(scheme, "scheme cannot be null");
            if (draft03 && !(scheme instanceof FlexfecScheme.Mask)) {
                throw new IllegalArgumentException("flexfec-03 supports only the flexible mask scheme");
            }
        }

        /// Creates a FlexFEC configuration with flexible masks, the scheme browsers use.
        ///
        /// @param payloadType       the payload type negotiated for `flexfec` or `flexfec-03`
        /// @param ssrc              the FlexFEC SSRC
        /// @param draft03           whether the negotiated format is `flexfec-03`
        /// @param protectionPercent the FEC packets per media packet in percent
        /// @throws IllegalArgumentException if a field is out of range
        public Flexfec(int payloadType, long ssrc, boolean draft03, int protectionPercent) {
            this(payloadType, ssrc, draft03, protectionPercent, new FlexfecScheme.Mask());
        }

        /// {@return a copy using `scheme`}
        ///
        /// @param scheme the scheme
        /// @throws IllegalArgumentException if this configuration uses the `flexfec-03` layout and `scheme` is not
        ///                                  [FlexfecScheme.Mask]
        public Flexfec withScheme(FlexfecScheme scheme) {
            return new Flexfec(payloadType, ssrc, draft03, protectionPercent, scheme);
        }
    }

    /// How a FlexFEC sender picks the packets each repair packet protects (RFC 8627 section 4.2.2).
    sealed interface FlexfecScheme {
        /// Flexible masks (`R=0, F=0`): per frame, the protection rate's share of repair packets, each protecting an
        /// interleaved or random-loss set of the frame's packets as the loss pattern asks; the scheme browsers use.
        record Mask() implements FlexfecScheme {
        }

        /// Fixed rows and columns (`R=0, F=1`): the media packets are laid out in blocks of `columns` by `rows`
        /// consecutive sequence numbers; with `rowParity` each completed row of `columns` packets gets one repair
        /// packet (1-D row FEC, the protection against random loss), and with `rows` above one each completed
        /// column of `rows` packets gets one too (column FEC against bursts up to `columns` long; both together
        /// are 2-D FEC). Repair packets leave as soon as their row or column is complete, whatever the frame
        /// boundaries; a gap in the media sequence restarts the block.
        ///
        /// @param columns   the packets of a row, `L`, `1..255`
        /// @param rows      the rows of a block, `D`: `0` for rows only, else `2..255`
        /// @param rowParity whether rows are protected; must be `true` when `rows` is `0`
        record RowColumn(int columns, int rows, boolean rowParity) implements FlexfecScheme {
            /// Validates the ranges.
            ///
            /// @throws IllegalArgumentException if a field is out of range, or nothing would be protected
            public RowColumn {
                if (columns < 1 || columns > 255) {
                    throw new IllegalArgumentException("columns must be in 1..255: " + columns);
                }
                if (rows != 0 && (rows < 2 || rows > 255)) {
                    throw new IllegalArgumentException("rows must be 0 or in 2..255: " + rows);
                }
                if (rows == 0 && !rowParity) {
                    throw new IllegalArgumentException("rows only needs rowParity");
                }
            }
        }

        /// Retransmission (`R=1`): repair packets repeat whole media packets, the protection rate's share of each
        /// frame (the marker packet first), and NACKed packets are repeated the same way when no RTX stream was
        /// negotiated.
        record Retransmission() implements FlexfecScheme {
        }
    }
}
