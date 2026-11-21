package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// Generates the FEC payloads protecting the media packets of one stream, one batch (usually one video frame) at a
/// time.
///
/// For a batch of `k` packets and a protection rate of `p` percent it emits `ceil(k * p / 100)` FEC payloads, FEC
/// payload `j` protecting every packet whose index modulo the FEC count is `j`; so any single loss among the packets
/// one payload protects is recoverable, and with full protection a burst of up to one loss per payload. A batch
/// spanning more sequence numbers than one FEC header can list is split into groups. An encoder is not
/// thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public final class FecEncoder {
    private final FecFormat format;
    private final long protectedSsrc;
    private int protectionPercent;
    private final List<RtpPacket> batch = new ArrayList<>();

    /// Creates an encoder.
    ///
    /// @param format            the FEC format
    /// @param protectedSsrc     the SSRC of the protected stream
    /// @param protectionPercent the FEC payloads per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public FecEncoder(FecFormat format, long protectedSsrc, int protectionPercent) {
        this.format = Objects.requireNonNull(format, "format cannot be null");
        this.protectedSsrc = protectedSsrc;
        setProtectionPercent(protectionPercent);
    }

    /// Changes the protection rate for the next batches.
    ///
    /// @param protectionPercent the FEC payloads per media packet in percent, `0..100`
    /// @throws IllegalArgumentException if `protectionPercent` is out of range
    public void setProtectionPercent(int protectionPercent) {
        if (protectionPercent < 0 || protectionPercent > 100) {
            throw new IllegalArgumentException("protectionPercent must be in 0..100: " + protectionPercent);
        }
        this.protectionPercent = protectionPercent;
    }

    /// {@return the FEC format}
    public FecFormat format() {
        return format;
    }

    /// Adds a media packet to the current batch.
    ///
    /// @param media the packet, as sent (before RED encapsulation for ULPFEC); its bytes are copied
    public void add(RtpPacket media) {
        batch.add(media.copy());
    }

    /// Ends the current batch.
    ///
    /// @return the FEC payloads protecting the batch, new heap buffers; empty when the rate is zero or the batch is
    ///         empty
    public List<ByteBuffer> flush() {
        if (batch.isEmpty() || protectionPercent == 0) {
            batch.clear();
            return List.of();
        }
        var out = new ArrayList<ByteBuffer>();
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
                for (var i = j; i < group.size(); i += count) {
                    protectedPackets.add(group.get(i));
                }
                out.add(FecCodec.encode(format, protectedSsrc, protectedPackets));
            }
            start = end;
        }
        batch.clear();
        return List.copyOf(out);
    }
}
