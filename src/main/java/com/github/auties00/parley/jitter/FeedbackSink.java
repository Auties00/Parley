package com.github.auties00.parley.jitter;

import java.util.List;

/// Where a [VideoFrameAssembler] sends the feedback it asks of the sender: a keyframe request (a PLI, or a FIR when
/// the stream has no PLI) and retransmission requests (generic NACKs).
///
/// The assembler calls the sink outside its own lock, on the thread that inserted a packet or polled for a frame;
/// the sink may block briefly to send RTCP but must not call back into the assembler.
///
/// @implSpec An implementation sends the requests to the stream's sender, or drops the ones the session did not
/// negotiate (no `nack`, no `nack pli`). It must be safe to call from any thread, one call at a time per assembler.
/// @spec https://www.rfc-editor.org/rfc/rfc4585.html RFC 4585: Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)
/// @spec https://www.rfc-editor.org/rfc/rfc5104.html RFC 5104: Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)
public interface FeedbackSink {
    /// A sink that drops every request.
    FeedbackSink NONE = new FeedbackSink() {
        @Override
        public void requestKeyframe() {
        }

        @Override
        public void requestRetransmission(List<Integer> sequences) {
        }
    };

    /// Asks the sender for a keyframe, because the stream cannot be decoded until one arrives.
    void requestKeyframe();

    /// Asks the sender to retransmit packets.
    ///
    /// @param sequences the 16-bit sequence numbers of the missing packets, in increasing order, unmodifiable
    void requestRetransmission(List<Integer> sequences);
}
