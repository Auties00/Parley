package com.github.auties00.parley.jitter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/// Aligns the playout of the streams one sender captured together (the audio and video tracks of one `a=msid` media
/// stream), so that media captured at the same instant plays at the same instant: lip sync.
///
/// Each member measures its end-to-end delay, from the sender's capture clock (the capture time of the frames it hands
/// out) to its own playout instant. Once per [#UPDATE_INTERVAL] the group gives every member that plays earlier than
/// the slowest one an extra delay of the difference, up to [#MAXIMUM_DELAY]: an [AudioPlayoutBuffer] raises its
/// target delay by it, a [VideoFrameAssembler] holds each decodable frame back by it. Members whose streams carry no
/// capture clock (neither `abs-capture-time` nor RTCP sender reports) do not take part until they do.
///
/// {@snippet lang = java :
/// var sync = SyncGroup.create();
/// sync.add(audioBuffer);
/// sync.add(videoAssembler);
/// }
///
/// # Requirements
///
/// The members must use the same [MonotonicClock][com.github.auties00.parley.net.MonotonicClock], since their delays
/// are compared, and their streams must come from one sender (one RTCP CNAME), whose capture clock they share.
///
/// # Threading
///
/// All methods are safe to call from any thread. The members update the group after each frame they hand out,
/// outside their own locks.
///
/// @implNote This implementation measures the delays the members actually play with, so a change takes effect
/// only once a member has absorbed it, and moves each extra delay by at most [#MAXIMUM_STEP] per update: an audio
/// buffer grows its delay by concealing frames at most once every ten frames, and stepping faster than that would
/// overshoot. This is the pace webrtc.org's stream synchronization keeps.
/// @spec https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.1 RFC 3550 section 6.4.1: SR: Sender Report RTCP Packet
/// @spec https://www.rfc-editor.org/rfc/rfc8830.html RFC 8830: WebRTC MediaStream Identification in the Session Description Protocol
public final class SyncGroup {
    /// The largest extra delay the group adds to one member.
    public static final Duration MAXIMUM_DELAY = Duration.ofSeconds(3);
    /// The largest change of a member's extra delay in one update.
    public static final Duration MAXIMUM_STEP = Duration.ofMillis(80);
    /// The time between two updates.
    public static final Duration UPDATE_INTERVAL = Duration.ofSeconds(1);

    /// One synchronized stream.
    interface Member {
        /// {@return the member's end-to-end delay, in nanoseconds: its playout clock minus the capture clock of the
        /// last frame it handed out, extra delay included, or an empty optional when unknown}
        OptionalLong delayNanos();

        /// {@return the extra delay the group asked for, in nanoseconds}
        long syncDelayNanos();

        /// Sets the extra delay the member adds to its playout.
        ///
        /// @param nanos the delay, `0..MAXIMUM_DELAY`
        void setSyncDelayNanos(long nanos);

        /// Joins or leaves a group, leaving the previous one.
        ///
        /// @param group the group, or `null` to leave
        void joinGroup(SyncGroup group);
    }

    /// The lock that guards every field below.
    private final Object lock = new Object();
    /// The members.
    private final List<Member> members = new ArrayList<>();
    /// The clock time of the last update, or `Long.MIN_VALUE`.
    private long lastUpdateNanos = Long.MIN_VALUE;

    private SyncGroup() {
    }

    /// {@return a new, empty group}
    public static SyncGroup create() {
        return new SyncGroup();
    }

    /// Adds an audio stream; a stream belongs to at most one group, so it leaves the one it was in.
    ///
    /// @param buffer the stream's playout buffer
    public void add(AudioPlayoutBuffer buffer) {
        addMember(Objects.requireNonNull(buffer, "buffer cannot be null").syncMember());
    }

    /// Adds a video stream; a stream belongs to at most one group, so it leaves the one it was in.
    ///
    /// @param assembler the stream's frame assembler
    public void add(VideoFrameAssembler assembler) {
        addMember(Objects.requireNonNull(assembler, "assembler cannot be null").syncMember());
    }

    /// Removes an audio stream, which then plays without extra delay; removing a stream that is not a member does
    /// nothing.
    ///
    /// @param buffer the stream's playout buffer
    public void remove(AudioPlayoutBuffer buffer) {
        removeMember(Objects.requireNonNull(buffer, "buffer cannot be null").syncMember());
    }

    /// Removes a video stream, which then plays without extra delay; removing a stream that is not a member does
    /// nothing.
    ///
    /// @param assembler the stream's frame assembler
    public void remove(VideoFrameAssembler assembler) {
        removeMember(Objects.requireNonNull(assembler, "assembler cannot be null").syncMember());
    }

    /// {@return the number of members}
    public int size() {
        synchronized (lock) {
            return members.size();
        }
    }

    /// {@return the extra delay the group currently asks of an audio stream, zero when it is not a member}
    ///
    /// @param buffer the stream's playout buffer
    public Duration delayOf(AudioPlayoutBuffer buffer) {
        return delayOfMember(Objects.requireNonNull(buffer, "buffer cannot be null").syncMember());
    }

    /// {@return the extra delay the group currently asks of a video stream, zero when it is not a member}
    ///
    /// @param assembler the stream's frame assembler
    public Duration delayOf(VideoFrameAssembler assembler) {
        return delayOfMember(Objects.requireNonNull(assembler, "assembler cannot be null").syncMember());
    }

    /// Adds a member, taking it out of the group it was in.
    private void addMember(Member member) {
        synchronized (lock) {
            if (members.contains(member)) {
                return;
            }
        }
        member.joinGroup(this);
        synchronized (lock) {
            members.add(member);
        }
    }

    /// Removes a member and clears its extra delay.
    private void removeMember(Member member) {
        boolean removed;
        synchronized (lock) {
            removed = members.remove(member);
        }
        if (removed) {
            member.joinGroup(null);
            member.setSyncDelayNanos(0);
        }
    }

    /// {@return the extra delay of a member}
    private Duration delayOfMember(Member member) {
        synchronized (lock) {
            return members.contains(member) ? Duration.ofNanos(member.syncDelayNanos()) : Duration.ZERO;
        }
    }

    /// Forgets a member that joined another group or closed.
    void detach(Member member) {
        synchronized (lock) {
            members.remove(member);
        }
    }

    /// Recomputes the extra delay of every member from the delays they measure, at most once per
    /// [#UPDATE_INTERVAL]; members call it after handing out a frame, outside their locks.
    ///
    /// @param nowNanos the members' clock
    void update(long nowNanos) {
        synchronized (lock) {
            if (lastUpdateNanos != Long.MIN_VALUE && nowNanos - lastUpdateNanos < UPDATE_INTERVAL.toNanos()) {
                return;
            }
            lastUpdateNanos = nowNanos;
            var count = members.size();
            var delays = new long[count];
            var known = new boolean[count];
            var slowest = Long.MIN_VALUE;
            for (var index = 0; index < count; index++) {
                var delay = members.get(index).delayNanos();
                if (delay.isPresent()) {
                    delays[index] = delay.getAsLong();
                    known[index] = true;
                    slowest = Math.max(slowest, delays[index]);
                }
            }
            var wanted = new long[count];
            var smallest = Long.MAX_VALUE;
            for (var index = 0; index < count; index++) {
                var extra = members.get(index).syncDelayNanos();
                wanted[index] = known[index] ? extra + slowest - delays[index] : 0;
                if (known[index]) {
                    smallest = Math.min(smallest, wanted[index]);
                }
            }
            var step = MAXIMUM_STEP.toNanos();
            for (var index = 0; index < count; index++) {
                var member = members.get(index);
                var current = member.syncDelayNanos();
                var target = known[index] ? Math.clamp(wanted[index] - smallest, 0, MAXIMUM_DELAY.toNanos()) : 0;
                var next = Math.clamp(target, current - step, current + step);
                if (next != current) {
                    member.setSyncDelayNanos(next);
                }
            }
        }
    }
}
