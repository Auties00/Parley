package com.github.auties00.parley.rtp.session;

/// Range checks shared by the session records.
final class SessionChecks {
    private SessionChecks() {
        throw new AssertionError("SessionChecks cannot be instantiated");
    }

    static void payloadType(int payloadType, String name) {
        if (payloadType < 0 || payloadType > 127) {
            throw new IllegalArgumentException(name + " must be in 0..127: " + payloadType);
        }
    }

    static void ssrc(long ssrc, String name) {
        if (ssrc < 0 || ssrc > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(name + " must be an unsigned 32-bit value: " + ssrc);
        }
    }

    static void percent(int percent) {
        if (percent < 0 || percent > 100) {
            throw new IllegalArgumentException("protectionPercent must be in 0..100: " + percent);
        }
    }

    static void clockRate(int clockRate) {
        if (clockRate <= 0) {
            throw new IllegalArgumentException("clockRate must be positive: " + clockRate);
        }
    }
}
