package com.github.auties00.parley.rtp.rtcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// An extended report (`XR`): report blocks beyond the reception statistics of sender and receiver reports.
///
/// Parley models the two blocks that give a receive-only participant a round-trip time: the receiver reference time
/// ([ReceiverReferenceTime], `RRTR`) a receiver sends, and the delay since the last one ([Dlrr], `DLRR`) its peer
/// answers with. Every other block type is kept as an [UnknownBlock].
///
/// @param ssrc   the reporter, an unsigned 32-bit value
/// @param blocks the report blocks, in order
/// @spec https://www.rfc-editor.org/rfc/rfc3611.html RFC 3611: RTP Control Protocol Extended Reports (RTCP XR)
public record ExtendedReport(long ssrc, List<Block> blocks) implements RtcpPacket {
    /// Validates `ssrc` and copies `blocks`.
    ///
    /// @throws IllegalArgumentException if `ssrc` is out of range
    public ExtendedReport {
        RtcpCodec.checkUint32(ssrc, "ssrc");
        blocks = List.copyOf(Objects.requireNonNull(blocks, "blocks cannot be null"));
    }

    /// One extended report block.
    public sealed interface Block permits ReceiverReferenceTime, Dlrr, UnknownBlock {
        /// {@return the block type (`BT`)}
        int blockType();

        /// {@return the encoded size, the 4-byte block header included}
        int encodedLength();
    }

    /// A receiver reference time block (`BT = 4`): the wall clock time at which the reporter sent this report.
    ///
    /// @param ntpTimestamp the 64-bit NTP timestamp
    public record ReceiverReferenceTime(long ntpTimestamp) implements Block {
        /// The block type.
        public static final int TYPE = 4;

        @Override
        public int blockType() {
            return TYPE;
        }

        @Override
        public int encodedLength() {
            return 12;
        }
    }

    /// A delay since last receiver report block (`BT = 5`): for each receiver whose reference time the reporter
    /// received, when it was received.
    ///
    /// @param entries the sub-blocks, one per receiver
    public record Dlrr(List<DlrrEntry> entries) implements Block {
        /// The block type.
        public static final int TYPE = 5;

        /// Copies `entries`.
        public Dlrr {
            entries = List.copyOf(Objects.requireNonNull(entries, "entries cannot be null"));
        }

        @Override
        public int blockType() {
            return TYPE;
        }

        @Override
        public int encodedLength() {
            return 4 + 12 * entries.size();
        }
    }

    /// One sub-block of a [Dlrr] block.
    ///
    /// @param ssrc                      the receiver whose reference time is answered, an unsigned 32-bit value
    /// @param lastReceiverReport        the middle 32 bits of the NTP timestamp of its last reference time block
    ///                                  (`LRR`)
    /// @param delaySinceLastReceiverReport the delay since receiving that block, in units of `1/65536` second
    ///                                  (`DLRR`)
    public record DlrrEntry(long ssrc, long lastReceiverReport, long delaySinceLastReceiverReport) {
        /// Validates the ranges.
        ///
        /// @throws IllegalArgumentException if a field is not an unsigned 32-bit value
        public DlrrEntry {
            RtcpCodec.checkUint32(ssrc, "ssrc");
            RtcpCodec.checkUint32(lastReceiverReport, "lastReceiverReport");
            RtcpCodec.checkUint32(delaySinceLastReceiverReport, "delaySinceLastReceiverReport");
        }
    }

    /// A block of a type Parley does not interpret, kept byte for byte.
    ///
    /// @param blockType    the block type, `0..255`
    /// @param typeSpecific the type-specific byte of the block header, `0..255`
    /// @param data         the block content after its header, a multiple of four bytes; kept as a read-only copy
    public record UnknownBlock(int blockType, int typeSpecific, ByteBuffer data) implements Block {
        /// Validates the fields and copies `data`.
        ///
        /// @throws IllegalArgumentException if a field is out of range or `data` is not a multiple of four bytes
        public UnknownBlock {
            if (blockType < 0 || blockType > 255 || typeSpecific < 0 || typeSpecific > 255) {
                throw new IllegalArgumentException("block type and type-specific byte must be in 0..255");
            }
            data = RtcpCodec.copyOf(Objects.requireNonNull(data, "data cannot be null"));
            if (data.remaining() % 4 != 0) {
                throw new IllegalArgumentException("data length must be a multiple of four: " + data.remaining());
            }
        }

        @Override
        public ByteBuffer data() {
            return data.duplicate();
        }

        @Override
        public int encodedLength() {
            return 4 + data.remaining();
        }
    }

    static ExtendedReport parse(ByteBuffer body) throws RtcpFormatException {
        RtcpCodec.requireRemaining(body, 4, "XR");
        var ssrc = RtcpCodec.uint32(body);
        var blocks = new ArrayList<Block>();
        while (body.hasRemaining()) {
            RtcpCodec.requireRemaining(body, 4, "XR block header");
            var type = body.get() & 0xFF;
            var typeSpecific = body.get() & 0xFF;
            var length = 4 * (body.getShort() & 0xFFFF);
            RtcpCodec.requireRemaining(body, length, "XR block");
            var content = body.slice(body.position(), length);
            body.position(body.position() + length);
            blocks.add(switch (type) {
                case ReceiverReferenceTime.TYPE -> {
                    if (length != 8) {
                        throw new RtcpFormatException("RRTR block length is not 8: " + length);
                    }
                    yield new ReceiverReferenceTime(content.getLong());
                }
                case Dlrr.TYPE -> {
                    if (length % 12 != 0) {
                        throw new RtcpFormatException("DLRR block length is not a multiple of 12: " + length);
                    }
                    var entries = new ArrayList<DlrrEntry>(length / 12);
                    while (content.hasRemaining()) {
                        entries.add(new DlrrEntry(RtcpCodec.uint32(content), RtcpCodec.uint32(content),
                                RtcpCodec.uint32(content)));
                    }
                    yield new Dlrr(entries);
                }
                default -> new UnknownBlock(type, typeSpecific, content);
            });
        }
        return new ExtendedReport(ssrc, blocks);
    }

    @Override
    public int encodedLength() {
        var length = RtcpCodec.HEADER_LENGTH + 4;
        for (var block : blocks) {
            length += block.encodedLength();
        }
        return length;
    }

    @Override
    public int writeTo(ByteBuffer destination) {
        var length = encodedLength();
        if (destination.remaining() < length) {
            throw new java.nio.BufferOverflowException();
        }
        RtcpCodec.writeHeader(destination, 0, EXTENDED_REPORT, length);
        destination.putInt((int) ssrc);
        for (var block : blocks) {
            var words = (block.encodedLength() - 4) / 4;
            switch (block) {
                case ReceiverReferenceTime(var ntp) -> {
                    destination.put((byte) ReceiverReferenceTime.TYPE).put((byte) 0).putShort((short) words);
                    destination.putLong(ntp);
                }
                case Dlrr(var entries) -> {
                    destination.put((byte) Dlrr.TYPE).put((byte) 0).putShort((short) words);
                    for (var entry : entries) {
                        destination.putInt((int) entry.ssrc());
                        destination.putInt((int) entry.lastReceiverReport());
                        destination.putInt((int) entry.delaySinceLastReceiverReport());
                    }
                }
                case UnknownBlock unknown -> {
                    destination.put((byte) unknown.blockType()).put((byte) unknown.typeSpecific())
                            .putShort((short) words);
                    destination.put(unknown.data());
                }
            }
        }
        return length;
    }
}
