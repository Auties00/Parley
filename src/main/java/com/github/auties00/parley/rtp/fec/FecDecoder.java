package com.github.auties00.parley.rtp.fec;

import com.github.auties00.parley.rtp.RtpFormatException;
import com.github.auties00.parley.rtp.RtpPacket;
import com.github.auties00.parley.rtp.SequenceNumbers;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/// Recovers lost media packets of one stream from the FEC packets that protect it.
///
/// The decoder keeps copies of the last [#MEDIA_WINDOW] media packets and of the last [#FEC_WINDOW] FEC payloads that
/// could not recover anything yet; each new packet of either kind retries every pending FEC payload, so recoveries
/// chain (a recovered packet can complete another payload). A decoder is not thread-safe.
///
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
public final class FecDecoder {
    /// The media packets kept for recovery.
    public static final int MEDIA_WINDOW = 512;
    /// The FEC payloads kept while they cannot recover anything.
    public static final int FEC_WINDOW = 64;

    private final FecFormat format;
    private final long protectedSsrc;
    private final Map<Integer, RtpPacket> media = new HashMap<>();
    private final LinkedList<Integer> mediaOrder = new LinkedList<>();
    private final LinkedList<FecCodec.Parsed> pending = new LinkedList<>();
    private int newest = -1;
    private long recovered;

    /// Creates a decoder.
    ///
    /// @param format        the FEC format
    /// @param protectedSsrc the SSRC of the protected media stream
    public FecDecoder(FecFormat format, long protectedSsrc) {
        this.format = Objects.requireNonNull(format, "format cannot be null");
        this.protectedSsrc = protectedSsrc;
    }

    /// Records a received (or otherwise recovered) media packet.
    ///
    /// @param packet a packet of the protected stream, as protected (without RED encapsulation for ULPFEC); its
    ///               bytes are copied
    /// @return the packets this one let the decoder recover, new heap packets; usually empty
    public List<RtpPacket> addMedia(RtpPacket packet) {
        if (packet.ssrc() != protectedSsrc || media.containsKey(packet.sequence())) {
            return List.of();
        }
        store(packet.copy());
        return tryRecover();
    }

    /// Records a received FEC payload.
    ///
    /// @param payload the FEC payload: the RED block data for ULPFEC, the RTP payload of a FlexFEC packet; it is not
    ///                modified and not retained
    /// @return the packets this payload let the decoder recover, new heap packets
    /// @throws RtpFormatException if the payload is malformed or uses an unsupported FlexFEC variant
    public List<RtpPacket> addFec(ByteBuffer payload) throws RtpFormatException {
        var parsed = FecCodec.parse(format, payload);
        if (parsed.protectedSsrc().isPresent() && parsed.protectedSsrc().getAsLong() != protectedSsrc) {
            return List.of();
        }
        if (parsed.protectedSequences().length == 0) {
            return List.of();
        }
        pending.addLast(parsed);
        while (pending.size() > FEC_WINDOW) {
            pending.removeFirst();
        }
        return tryRecover();
    }

    /// {@return the number of packets recovered since the decoder was created}
    public long recoveredCount() {
        return recovered;
    }

    private void store(RtpPacket packet) {
        var sequence = packet.sequence();
        media.put(sequence, packet);
        mediaOrder.addLast(sequence);
        if (newest < 0 || SequenceNumbers.isNewer(sequence, newest)) {
            newest = sequence;
        }
        while (mediaOrder.size() > MEDIA_WINDOW) {
            media.remove(mediaOrder.removeFirst());
        }
    }

    private List<RtpPacket> tryRecover() {
        var out = new ArrayList<RtpPacket>();
        var progress = true;
        while (progress) {
            progress = false;
            for (Iterator<FecCodec.Parsed> iterator = pending.iterator(); iterator.hasNext(); ) {
                var fec = iterator.next();
                var sequences = fec.protectedSequences();
                if (newest >= 0 && SequenceNumbers.difference(newest, sequences[sequences.length - 1])
                        > MEDIA_WINDOW) {
                    iterator.remove();
                    continue;
                }
                var missing = -1;
                var missingCount = 0;
                var present = new ArrayList<RtpPacket>(sequences.length);
                for (var sequence : sequences) {
                    var packet = media.get(sequence);
                    if (packet == null) {
                        missing = sequence;
                        missingCount++;
                    } else {
                        present.add(packet);
                    }
                }
                if (missingCount == 0) {
                    iterator.remove();
                } else if (missingCount == 1) {
                    iterator.remove();
                    try {
                        var packet = FecCodec.recover(fec.parity(), present, missing, protectedSsrc);
                        store(packet);
                        out.add(packet);
                        recovered++;
                        progress = true;
                    } catch (RtpFormatException ignored) {
                        // a parity block that does not rebuild a valid packet protects nothing usable
                    }
                }
            }
        }
        return out;
    }
}
