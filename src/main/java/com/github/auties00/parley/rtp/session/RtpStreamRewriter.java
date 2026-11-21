package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.SequenceNumbers;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;

/// Rewrites the packets of several source streams into one continuous output stream: the SFU helper that forwards
/// one simulcast layer at a time to a receiver and switches layers without the receiver seeing a new stream.
///
/// The output keeps one SSRC, a sequence number space without gaps or jumps across switches (gaps from loss
/// upstream are kept, so the receiver still NACKs them) and a timestamp line that advances by the wall time between
/// the last packet of the old source and the first of the new one. A switch requested with [#switchTo(long)] takes
/// effect at the next packet of the new source passed as a switch point (the first packet of a keyframe, which the
/// payload format tells), so the receiver's decoder can start on it; until then the old source keeps flowing.
///
/// Only the fixed header is rewritten. Header extensions, payload descriptors (VP8 picture id and TL0PICIDX, the AV1
/// dependency descriptor's frame number) and RTCP are the caller's to translate; [#sourceOf(int)] maps a NACKed
/// output sequence number back to the source packet.
///
/// A rewriter is not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7667.html RFC 7667: RTP Topologies
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
public final class RtpStreamRewriter {
    /// The output sequence numbers remembered for [#sourceOf(int)].
    public static final int SOURCE_WINDOW = 2048;

    private final long outputSsrc;
    private final int clockRate;
    private long activeSource = -1;
    private long pendingSource = -1;
    private int sequenceOffset;
    private long timestampOffset;
    private int switchBase;
    private boolean started;
    private int lastSequence;
    private long lastTimestamp;
    private long lastArrivalNanos;
    private final long[] sources = new long[SOURCE_WINDOW];
    private final int[] sourceSequences = new int[SOURCE_WINDOW];
    private final int[] outputSequences = new int[SOURCE_WINDOW];

    /// The source packet an output sequence number came from.
    ///
    /// @param ssrc     the source SSRC
    /// @param sequence the source sequence number
    public record SourcePacket(long ssrc, int sequence) {
    }

    private RtpStreamRewriter(long outputSsrc, int clockRate) {
        this.outputSsrc = outputSsrc;
        this.clockRate = clockRate;
        java.util.Arrays.fill(outputSequences, -1);
    }

    /// Creates a rewriter.
    ///
    /// @param outputSsrc the SSRC of the output stream, an unsigned 32-bit value
    /// @param clockRate  the RTP clock rate shared by the sources, in hertz
    /// @return the rewriter, forwarding nothing until the first [#switchTo(long)]
    /// @throws IllegalArgumentException if a value is out of range
    public static RtpStreamRewriter create(long outputSsrc, int clockRate) {
        SessionChecks.ssrc(outputSsrc, "outputSsrc");
        SessionChecks.clockRate(clockRate);
        return new RtpStreamRewriter(outputSsrc, clockRate);
    }

    /// {@return the output SSRC}
    public long outputSsrc() {
        return outputSsrc;
    }

    /// {@return the source currently forwarded, if any}
    public Optional<Long> activeSource() {
        return activeSource < 0 ? Optional.empty() : Optional.of(activeSource);
    }

    /// Requests a switch to another source at its next switch point.
    ///
    /// @param sourceSsrc the source SSRC; requesting the active source cancels a pending switch
    public void switchTo(long sourceSsrc) {
        SessionChecks.ssrc(sourceSsrc, "sourceSsrc");
        pendingSource = sourceSsrc == activeSource ? -1 : sourceSsrc;
    }

    /// Rewrites one source packet.
    ///
    /// @param packet       a packet of any source
    /// @param switchPoint  whether a decoder can start at the packet (the first packet of a keyframe)
    /// @param arrivalNanos when the packet arrived, in nanoseconds of any monotonic clock
    /// @param tailroom     spare bytes to leave after the rewritten packet, such as the SRTP overhead
    /// @return the rewritten packet in a new heap buffer, positioned at zero, or empty when the packet is not
    ///         forwarded (another source, or older than the switch to its source)
    public Optional<ByteBuffer> rewrite(RtpPacket packet, boolean switchPoint, long arrivalNanos, int tailroom) {
        Objects.requireNonNull(packet, "packet cannot be null");
        if (tailroom < 0) {
            throw new IllegalArgumentException("tailroom cannot be negative: " + tailroom);
        }
        if (packet.ssrc() == pendingSource && switchPoint) {
            if (started) {
                sequenceOffset = (lastSequence + 1 - packet.sequence()) & 0xFFFF;
                var elapsed = Math.max(0, arrivalNanos - lastArrivalNanos);
                var ticks = Math.max(1, (elapsed / 1_000_000_000L) * clockRate
                        + (elapsed % 1_000_000_000L) * clockRate / 1_000_000_000L);
                timestampOffset = (lastTimestamp + ticks - packet.timestamp()) & 0xFFFFFFFFL;
            }
            activeSource = pendingSource;
            pendingSource = -1;
            switchBase = packet.sequence();
        }
        if (packet.ssrc() != activeSource || SequenceNumbers.isNewer(switchBase, packet.sequence())) {
            return Optional.empty();
        }
        var sequence = (packet.sequence() + sequenceOffset) & 0xFFFF;
        var timestamp = (packet.timestamp() + timestampOffset) & 0xFFFFFFFFL;
        var out = ByteBuffer.allocate(packet.length() + tailroom);
        out.put(packet.buffer());
        out.putShort(2, (short) sequence);
        out.putInt(4, (int) timestamp);
        out.putInt(8, (int) outputSsrc);
        out.flip();
        if (!started || SequenceNumbers.isNewer(sequence, lastSequence)) {
            lastSequence = sequence;
            lastTimestamp = timestamp;
            lastArrivalNanos = arrivalNanos;
            started = true;
        }
        var slot = sequence % SOURCE_WINDOW;
        sources[slot] = packet.ssrc();
        sourceSequences[slot] = packet.sequence();
        outputSequences[slot] = sequence;
        return Optional.of(out);
    }

    /// {@return the source packet an output sequence number was rewritten from, while it is among the last
    /// [#SOURCE_WINDOW]}
    ///
    /// @param outputSequence an output sequence number, `0..65535`
    public Optional<SourcePacket> sourceOf(int outputSequence) {
        var slot = (outputSequence & 0xFFFF) % SOURCE_WINDOW;
        if (outputSequences[slot] != (outputSequence & 0xFFFF)) {
            return Optional.empty();
        }
        return Optional.of(new SourcePacket(sources[slot], sourceSequences[slot]));
    }
}
