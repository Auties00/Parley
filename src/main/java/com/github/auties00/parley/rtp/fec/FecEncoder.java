package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// Generates the repair payloads protecting the media packets of one stream.
///
/// An encoder follows one of three schemes:
///
/// - **Masks** ([#create(FecFormat, long, int)], ULPFEC and FlexFEC with flexible masks): one batch (usually one
///   video frame) at a time. For a batch of `k` packets and a protection rate of `p` percent it emits
///   `ceil(k * p / 100)` payloads, whose masks follow the [FecMaskType]: [FecMaskType#BURSTY] interleaves (payload
///   `j` protects every packet whose index modulo the payload count is `j`, so a burst of up to one loss per payload
///   is recoverable), [FecMaskType#RANDOM] adds to each interleaved set the contiguous block of the batch of the
///   same index, so most packets are protected twice and two scattered losses are recoverable more often. A batch
///   spanning more sequence numbers than one FEC header can list is split into groups.
/// - **Rows and columns** ([#rowColumn(long, int, int, boolean)], RFC 8627 `F=1`): media packets are laid out in
///   blocks of `L` columns by `D` rows of consecutive sequence numbers; each completed row and, for `D > 1`, each
///   completed column gets one payload. A gap in the sequence numbers starts a new block.
/// - **Retransmission** ([#retransmission(long, int)], RFC 8627 `R=1`): the protection rate's share of each batch
///   is repeated whole, the last packet (the marker packet) first.
///
/// Payloads are returned by [#flush()] at the end of each batch. An encoder is not thread-safe.
///
/// @implNote The two mask types are generated rather than read from libwebrtc's tables of hand-tuned masks; they
/// follow the same two designs (interleaved for bursts, overlapping for random loss).
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public final class FecEncoder {
    private enum Scheme {
        MASK, ROW_COLUMN, RETRANSMISSION
    }

    private final FecFormat format;
    private final Scheme scheme;
    private final long protectedSsrc;
    private final int columns;
    private final int rows;
    private final boolean rowParity;
    private int protectionPercent;
    private FecMaskType maskType = FecMaskType.RANDOM;
    private final List<RtpPacket> batch = new ArrayList<>();
    private final List<ByteBuffer> ready = new ArrayList<>();
    private int blockBase = -1;
    private int blockIndex;
    private int nextSequence = -1;
    private FecCodec.Parity row;
    private FecCodec.Parity[] columnParities;

    private FecEncoder(FecFormat format, Scheme scheme, long protectedSsrc, int protectionPercent, int columns,
                       int rows, boolean rowParity) {
        this.format = Objects.requireNonNull(format, "format cannot be null");
        this.scheme = scheme;
        this.protectedSsrc = protectedSsrc;
        this.columns = columns;
        this.rows = rows;
        this.rowParity = rowParity;
        setProtectionPercent(protectionPercent);
    }

    /// Creates a mask encoder.
    ///
    /// @param format            the FEC format
    /// @param protectedSsrc     the SSRC of the protected stream
    /// @param protectionPercent the FEC payloads per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public FecEncoder(FecFormat format, long protectedSsrc, int protectionPercent) {
        this(format, Scheme.MASK, protectedSsrc, protectionPercent, 0, 0, false);
    }

    /// {@return a mask encoder}
    ///
    /// @param format            the FEC format
    /// @param protectedSsrc     the SSRC of the protected stream
    /// @param protectionPercent the FEC payloads per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public static FecEncoder create(FecFormat format, long protectedSsrc, int protectionPercent) {
        return new FecEncoder(format, protectedSsrc, protectionPercent);
    }

    /// {@return an RFC 8627 encoder with fixed columns and rows}
    ///
    /// @param protectedSsrc the SSRC of the protected stream
    /// @param columns       `L`, the packets of a row, `1..255`
    /// @param rows          `D`, the rows of a block: `0` for rows only, else `2..255`
    /// @param rowParity     whether each row is protected
    /// @throws IllegalArgumentException if a value is out of range or nothing would be protected
    public static FecEncoder rowColumn(long protectedSsrc, int columns, int rows, boolean rowParity) {
        if (columns < 1 || columns > 255 || (rows != 0 && (rows < 2 || rows > 255)) || (rows == 0 && !rowParity)) {
            throw new IllegalArgumentException("invalid row and column layout: L=" + columns + ", D=" + rows);
        }
        return new FecEncoder(FecFormat.FLEXFEC, Scheme.ROW_COLUMN, protectedSsrc, 100, columns, rows, rowParity);
    }

    /// {@return an RFC 8627 retransmission encoder}
    ///
    /// @param protectedSsrc     the SSRC of the protected stream
    /// @param protectionPercent the packets repeated per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public static FecEncoder retransmission(long protectedSsrc, int protectionPercent) {
        return new FecEncoder(FecFormat.FLEXFEC, Scheme.RETRANSMISSION, protectedSsrc, protectionPercent, 0, 0,
                false);
    }

    /// {@return an RFC 8627 retransmission repair payload repeating one packet}
    ///
    /// @param packet the packet to repeat; its bytes are copied
    public static ByteBuffer retransmissionOf(RtpPacket packet) {
        return FecCodec.encodeRetransmission(packet);
    }

    /// Changes the protection rate for the next batches; ignored by a row and column encoder.
    ///
    /// @param protectionPercent the FEC payloads per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public void setProtectionPercent(int protectionPercent) {
        if (protectionPercent < 0 || protectionPercent > 100) {
            throw new IllegalArgumentException("protectionPercent must be in 0..100: " + protectionPercent);
        }
        this.protectionPercent = protectionPercent;
    }

    /// Changes the masks of the next batches of a mask encoder.
    ///
    /// @param maskType the mask type
    public void setMaskType(FecMaskType maskType) {
        this.maskType = Objects.requireNonNull(maskType, "maskType cannot be null");
    }

    /// {@return the mask type of the next batch}
    public FecMaskType maskType() {
        return maskType;
    }

    /// {@return the FEC format}
    public FecFormat format() {
        return format;
    }

    /// Adds a media packet to the current batch, keeping the packet itself rather than a copy.
    ///
    /// The encoder reads the packet's bytes until the next [#flush()] returns (the row and column scheme only while
    /// this method runs), so the caller must not change them before then: a sender that builds a frame's repair
    /// packets before sending any of the frame's packets passes them here and saves a copy per packet.
    ///
    /// @param media the packet, as sent (before RED encapsulation for ULPFEC)
    public void addOwned(RtpPacket media) {
        if (scheme == Scheme.ROW_COLUMN) {
            addToBlock(media);
        } else {
            batch.add(media);
        }
    }

    /// Adds a media packet to the current batch.
    ///
    /// @param media the packet, as sent (before RED encapsulation for ULPFEC); its bytes are copied
    public void add(RtpPacket media) {
        var copy = media.copy();
        if (scheme == Scheme.ROW_COLUMN) {
            addToBlock(copy);
        } else {
            batch.add(copy);
        }
    }

    /// Ends the current batch.
    ///
    /// @return the repair payloads ready, new heap buffers; empty when the rate is zero, the batch is empty, or no
    ///         row or column completed
    public List<ByteBuffer> flush() {
        var out = new ArrayList<>(ready);
        ready.clear();
        if (!batch.isEmpty() && protectionPercent > 0) {
            switch (scheme) {
                case MASK -> encodeMasks(out);
                case RETRANSMISSION -> encodeRetransmissions(out);
                case ROW_COLUMN -> {
                }
            }
        }
        batch.clear();
        return List.copyOf(out);
    }

    private void encodeMasks(List<ByteBuffer> out) {
        var start = 0;
        while (start < batch.size()) {
            var base = batch.get(start).sequence();
            var end = start;
            while (end < batch.size() && ((batch.get(end).sequence() - base) & 0xFFFF) < format.maxProtected()) {
                end++;
            }
            var group = batch.subList(start, end);
            var count = Math.max(1, (group.size() * protectionPercent + 99) / 100);
            count = Math.min(count, group.size());
            for (var j = 0; j < count; j++) {
                var protectedPackets = new ArrayList<RtpPacket>();
                for (var i = 0; i < group.size(); i++) {
                    if (protects(j, i, count, group.size())) {
                        protectedPackets.add(group.get(i));
                    }
                }
                out.add(FecCodec.encode(format, protectedSsrc, protectedPackets));
            }
            start = end;
        }
    }

    /// {@return whether payload `j` of `count` protects packet `i` of `size`, under the current mask type}
    boolean protects(int j, int i, int count, int size) {
        var interleaved = i % count == j;
        if (maskType == FecMaskType.BURSTY || count == 1) {
            return interleaved;
        }
        return interleaved || (long) i * count / size == j;
    }

    private void encodeRetransmissions(List<ByteBuffer> out) {
        var count = Math.min(batch.size(), Math.max(1, (batch.size() * protectionPercent + 99) / 100));
        var chosen = new boolean[batch.size()];
        for (var n = 0; n < count; n++) {
            var index = batch.size() - 1 - (int) ((long) n * batch.size() / count);
            chosen[index] = true;
        }
        for (var index = batch.size() - 1; index >= 0; index--) {
            if (chosen[index]) {
                out.add(FecCodec.encodeRetransmission(batch.get(index)));
            }
        }
    }

    private void addToBlock(RtpPacket packet) {
        if (blockBase < 0 || packet.sequence() != nextSequence) {
            startBlock(packet.sequence());
        }
        nextSequence = (packet.sequence() + 1) & 0xFFFF;
        var column = blockIndex % columns;
        var rowNumber = blockIndex / columns;
        if (rowParity) {
            row = (row == null ? FecCodec.Parity.empty() : row).plus(packet);
            if (column == columns - 1) {
                var rowBase = (blockBase + rowNumber * columns) & 0xFFFF;
                ready.add(FecCodec.encodeFixed(row, rowBase, columns, rows == 0 ? 0 : 1));
                row = null;
            }
        }
        if (rows > 1) {
            columnParities[column] = (columnParities[column] == null ? FecCodec.Parity.empty()
                    : columnParities[column]).plus(packet);
            if (rowNumber == rows - 1) {
                ready.add(FecCodec.encodeFixed(columnParities[column], (blockBase + column) & 0xFFFF, columns, rows));
                columnParities[column] = null;
            }
        }
        blockIndex++;
        if (rows > 1 && blockIndex == columns * rows) {
            blockBase = -1;
        } else if (rows == 0 && blockIndex == columns) {
            blockBase = -1;
        }
    }

    private void startBlock(int sequence) {
        blockBase = sequence;
        blockIndex = 0;
        row = null;
        columnParities = rows > 1 ? new FecCodec.Parity[columns] : null;
    }
}
