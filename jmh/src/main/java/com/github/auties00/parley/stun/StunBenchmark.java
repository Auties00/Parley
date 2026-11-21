package com.github.auties00.parley.stun;

import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.TimeUnit;

/// An ICE connectivity check: encoding with `MESSAGE-INTEGRITY` and `FINGERPRINT` (CRC-32), decoding (which checks
/// the fingerprint) and verifying the integrity.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class StunBenchmark {
    private StunMessage request;
    private StunKey key;
    private ByteBuffer encoded;
    private ByteBuffer destination;
    private StunMessage decoded;

    @Setup
    public void setup() throws StunFormatException {
        key = StunKey.shortTerm("x9cml/YzichV2+XlhiMu8g8P");
        request = StunMessage.request(StunMethod.BINDING, List.of(
                new StunAttribute.Username("abcd:efgh"),
                new StunAttribute.Priority(1853824767),
                new StunAttribute.IceControlling(0x0123456789ABCDEFL),
                new StunAttribute.UseCandidate()));
        encoded = request.encode(key, StunIntegrity.HMAC_SHA1, true);
        destination = ByteBuffer.allocate(256);
        decoded = StunMessage.decode(encoded);
    }

    /// Encodes the check with integrity and fingerprint into a reused buffer.
    @Benchmark
    public int encode() {
        destination.clear();
        return request.encodeTo(destination, key, StunIntegrity.HMAC_SHA1, true);
    }

    /// Decodes the check, verifying its fingerprint.
    @Benchmark
    public StunMessage decode() throws StunFormatException {
        return StunMessage.decode(encoded);
    }

    /// Verifies the integrity of a decoded check.
    @Benchmark
    public boolean verifyIntegrity() {
        return decoded.verifyIntegrity(key);
    }
}
