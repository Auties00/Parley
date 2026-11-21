package com.github.auties00.parley.sdp;

import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/// Parsing and serializing a Chrome offer (audio, video with RTX, a data channel; 109 lines).
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class SdpBenchmark {
    private String text;
    private SessionDescription parsed;

    @Setup
    public void setup() throws IOException, SdpFormatException {
        try (var input = SdpBenchmark.class.getResourceAsStream("/chrome-offer.sdp")) {
            text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        parsed = SessionDescription.parse(text);
    }

    @Benchmark
    public SessionDescription parse() throws SdpFormatException {
        return SessionDescription.parse(text);
    }

    @Benchmark
    public String serialize() {
        return parsed.encode();
    }
}
