package com.github.auties00.parley.cc;

import com.github.auties00.parley.rtp.session.SentPacket;
import com.github.auties00.parley.rtp.rtcp.TransportFeedback;
import com.github.auties00.parley.rtp.session.OutgoingPacketScheduler.Priority;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Random;

/// A discrete-event simulation of one media flow through a bottleneck: an encoder that follows the controller's
/// target, the controller's pacer, a drop-tail link of configurable capacity, propagation delay and random loss, a
/// transport-wide feedback generator at the receiver, and the reverse path back to the controller. All of it runs on
/// one [FakeClock], so a run is deterministic.
final class CongestionSimulation {
    static final long MS = 1_000_000L;

    private record Event(long atNanos, long order, Runnable action) {
    }

    final FakeClock clock;
    final GoogleCongestionController controller;
    final Pacer pacer;
    final TransportFeedbackGenerator receiver;
    final List<long[]> targets;
    private final PriorityQueue<Event> events;
    private final Random random;
    private long order;
    private long capacityBps;
    private long propagationNanos;
    private double lossRate;
    private long queueLimitBytes;
    private long encoderCapBps;
    private long linkFreeAtNanos;
    private int transportSequence;
    private long nextFrameNanos;
    private long nextFeedbackNanos;
    private long deliveredBytes;
    private long lastQueueDelayNanos;
    private boolean feedbackEnabled;

    CongestionSimulation(CongestionConfig config, long capacityBps) {
        this.clock = new FakeClock(1_000 * MS);
        this.targets = new ArrayList<>();
        this.controller = new GoogleCongestionController(config.withClock(clock)
                .withTargetListener(target -> targets.add(new long[]{target.atNanos(), target.bitsPerSecond()})), false);
        this.pacer = controller.pacer();
        this.events = new PriorityQueue<>((a, b) -> a.atNanos() != b.atNanos()
                ? Long.compare(a.atNanos(), b.atNanos()) : Long.compare(a.order(), b.order()));
        this.random = new Random(42);
        this.capacityBps = capacityBps;
        this.propagationNanos = 25 * MS;
        this.queueLimitBytes = Long.MAX_VALUE;
        this.encoderCapBps = Long.MAX_VALUE;
        this.feedbackEnabled = true;
        this.receiver = TransportFeedbackGenerator.create(2, clock, packet -> {
            var feedback = (TransportFeedback) packet;
            if (feedbackEnabled) {
                schedule(clock.nanos() + propagationNanos, () -> controller.onTransportFeedback(feedback, clock.nanos()));
            }
        });
        pacer.setPaddingSource((bytes, probe) -> {
            var size = Math.clamp(bytes, 200, 1200);
            transmit(size, Priority.PADDING);
            return size;
        });
        this.nextFrameNanos = clock.nanos();
        this.nextFeedbackNanos = clock.nanos() + 100 * MS;
    }

    void setCapacity(long capacityBps) {
        this.capacityBps = capacityBps;
    }

    void setLossRate(double lossRate) {
        this.lossRate = lossRate;
    }

    void setQueueLimitBytes(long queueLimitBytes) {
        this.queueLimitBytes = queueLimitBytes;
    }

    void setEncoderCap(long encoderCapBps) {
        this.encoderCapBps = encoderCapBps;
    }

    void setPropagationMillis(long millis) {
        this.propagationNanos = millis * MS;
    }

    /// {@return the current target}
    long target() {
        return controller.currentTarget().bitsPerSecond();
    }

    /// {@return the queueing delay the last packet met at the bottleneck}
    long lastQueueDelayMillis() {
        return lastQueueDelayNanos / MS;
    }

    /// {@return the bytes delivered through the bottleneck so far}
    long deliveredBytes() {
        return deliveredBytes;
    }

    /// Runs the simulation for `millis` of simulated time.
    void run(long millis) {
        var end = clock.nanos() + millis * MS;
        var pacerNext = clock.nanos();
        while (clock.nanos() < end) {
            var next = Math.min(Math.min(nextFrameNanos, nextFeedbackNanos), Math.max(pacerNext, clock.nanos() + 1));
            if (!events.isEmpty()) {
                next = Math.min(next, events.peek().atNanos());
            }
            next = Math.min(Math.max(next, clock.nanos()), end);
            clock.set(next);
            while (!events.isEmpty() && events.peek().atNanos() <= clock.nanos()) {
                events.poll().action().run();
            }
            if (clock.nanos() >= nextFrameNanos) {
                encodeFrame();
                nextFrameNanos += 1_000_000_000L / 30;
            }
            if (clock.nanos() >= nextFeedbackNanos) {
                receiver.sendFeedback();
                nextFeedbackNanos += 100 * MS;
            }
            pacerNext = pacer.process(clock.nanos());
        }
    }

    private void encodeFrame() {
        var rate = Math.min(target(), encoderCapBps);
        var bytes = (int) (rate / 8 / 30);
        while (bytes > 0) {
            var size = Math.min(bytes, 1200);
            bytes -= size;
            pacer.schedule(ByteBuffer.allocate(size), Priority.VIDEO, 1, packet -> transmit(packet.remaining(), Priority.VIDEO));
        }
    }

    private void transmit(int size, Priority priority) {
        var sequence = transportSequence++ & 0xFFFF;
        var now = clock.nanos();
        controller.onPacketSent(new SentPacket(sequence, size, now, priority, false, 1, sequence));
        if (random.nextDouble() < lossRate) {
            return;
        }
        var start = Math.max(now, linkFreeAtNanos);
        var queued = (start - now) * (double) capacityBps / 8e9;
        if (queued > queueLimitBytes) {
            return;
        }
        var finish = start + (long) (size * 8e9 / capacityBps);
        linkFreeAtNanos = finish;
        lastQueueDelayNanos = start - now;
        schedule(finish + propagationNanos, () -> {
            deliveredBytes += size;
            receiver.onPacketReceived(sequence, 1, clock.nanos());
        });
    }

    private void schedule(long atNanos, Runnable action) {
        events.add(new Event(atNanos, order++, action));
    }
}
