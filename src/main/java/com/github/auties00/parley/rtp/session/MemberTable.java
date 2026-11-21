package com.github.auties00.parley.rtp.session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/// The remote members of an RTP session (RFC 3550 section 6.2.1): every remote SSRC seen in RTP or RTCP, with what
/// the session remembers about it: when it was last heard from, the CNAME it announced and the receiver reference
/// time it asked to be answered.
///
/// SSRCs are chosen by the peer, so the table is bounded: at most [#CAPACITY] members, the least recently heard
/// from dropped first, and a member silent for longer than its timeout is forgotten by [#expire(long)]. Not
/// thread-safe: the session serializes access.
///
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html RFC 3550: RTP: A Transport Protocol for Real-Time Applications
final class MemberTable {
    /// The most members remembered, as many as the demultiplexer binds.
    static final int CAPACITY = RtpDemuxer.MAX_BINDINGS;

    /// What the session knows of one remote SSRC.
    static final class Member {
        long lastHeardNanos;
        boolean sentRtp;
        boolean sentSenderReport;
        String cname;
        long referenceTimeNtpCompact;
        long referenceTimeArrivalNanos = Long.MIN_VALUE;
    }

    private final long timeoutNanos;
    private final LinkedHashMap<Long, Member> members;
    private long evicted;

    /// Creates an empty table.
    ///
    /// @param timeoutNanos how long a silent member is kept
    MemberTable(long timeoutNanos) {
        this.timeoutNanos = timeoutNanos;
        this.members = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, Member> eldest) {
                if (size() > CAPACITY) {
                    evicted++;
                    return true;
                }
                return false;
            }
        };
    }

    /// {@return the member of an SSRC, recording that it was heard from now; created when unknown}
    ///
    /// @param ssrc     the SSRC
    /// @param nowNanos the time
    Member heard(long ssrc, long nowNanos) {
        var member = members.get(ssrc);
        if (member == null) {
            member = new Member();
            members.put(ssrc, member);
        }
        member.lastHeardNanos = nowNanos;
        return member;
    }

    /// {@return the member of an SSRC, without touching its recency}
    ///
    /// @param ssrc the SSRC
    Optional<Member> peek(long ssrc) {
        var member = members.get(ssrc);
        return Optional.ofNullable(member);
    }

    /// Forgets an SSRC, as a BYE asks.
    ///
    /// @param ssrc the SSRC
    void remove(long ssrc) {
        members.remove(ssrc);
    }

    /// Forgets every member silent for longer than the timeout.
    ///
    /// @param nowNanos the time
    void expire(long nowNanos) {
        members.values().removeIf(member -> nowNanos - member.lastHeardNanos >= timeoutNanos);
    }

    /// {@return the members heard from within the timeout}
    ///
    /// @param nowNanos the time
    int activeCount(long nowNanos) {
        var count = 0;
        for (var member : members.values()) {
            if (nowNanos - member.lastHeardNanos < timeoutNanos) {
                count++;
            }
        }
        return count;
    }

    /// A receiver reference time to answer with a DLRR entry.
    ///
    /// @param ssrc         the member that sent it
    /// @param ntpCompact   the middle 32 bits of its NTP timestamp
    /// @param arrivalNanos when it arrived
    record ReferenceTime(long ssrc, long ntpCompact, long arrivalNanos) {
    }

    /// {@return the receiver reference times to answer, newest first, at most `limit`; every pending one is cleared}
    ///
    /// @param limit the most to return
    List<ReferenceTime> takeReferenceTimes(int limit) {
        var pending = new ArrayList<ReferenceTime>();
        for (var entry : members.entrySet()) {
            var member = entry.getValue();
            if (member.referenceTimeArrivalNanos != Long.MIN_VALUE) {
                pending.add(new ReferenceTime(entry.getKey(), member.referenceTimeNtpCompact,
                        member.referenceTimeArrivalNanos));
                member.referenceTimeArrivalNanos = Long.MIN_VALUE;
            }
        }
        pending.sort((left, right) -> Long.compare(right.arrivalNanos(), left.arrivalNanos()));
        return List.copyOf(pending.subList(0, Math.min(limit, pending.size())));
    }

    /// {@return the members remembered}
    int size() {
        return members.size();
    }

    /// {@return the members dropped because the table was full}
    long evicted() {
        return evicted;
    }
}
