package com.github.auties00.parley.bytes;

import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/// The byte kernels, scalar against vectorized: XOR of a 1,200-byte parity body from an array and from a read-only
/// buffer (as FEC reads packets), and the search for the start code that ends a 5,000-byte NAL unit. `bytewise` is
/// the loop the kernels replaced: one `ByteBuffer.get` per byte.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class ByteKernelsBenchmark {
    @Param({"bytewise", "scalar", "vector"})
    public String kernels;

    private ByteKernels implementation;
    private byte[] target;
    private byte[] source;
    private ByteBuffer readOnly;
    private ByteBuffer stream;

    @Setup
    public void setup() {
        implementation = switch (kernels) {
            case "vector" -> VectorByteKernels.create();
            case "scalar", "bytewise" -> ByteKernels.scalar();
            default -> throw new IllegalArgumentException(kernels);
        };
        if (implementation == null) {
            throw new IllegalStateException("the vectorized kernels cannot run here");
        }
        var random = new Random(1);
        target = new byte[1200];
        source = new byte[1200];
        random.nextBytes(source);
        readOnly = ByteBuffer.wrap(source).asReadOnlyBuffer();
        var nal = new byte[5004];
        for (var index = 0; index < nal.length; index++) {
            nal[index] = (byte) (1 + random.nextInt(255));
        }
        nal[5000] = 0;
        nal[5001] = 0;
        nal[5002] = 1;
        stream = ByteBuffer.wrap(nal).asReadOnlyBuffer();
    }

    private boolean bytewise() {
        return kernels.equals("bytewise");
    }

    @Benchmark
    public byte[] xorArray() {
        implementation.xor(target, 0, source, 0, source.length);
        return target;
    }

    @Benchmark
    public byte[] xorReadOnlyBuffer() {
        if (bytewise()) {
            for (var i = 0; i < source.length; i++) {
                target[i] ^= readOnly.get(i);
            }
            return target;
        }
        implementation.xor(target, 0, readOnly, 0, source.length);
        return target;
    }

    @Benchmark
    public int startCode() {
        if (bytewise()) {
            var to = stream.limit();
            for (var i = 0; i + 2 < to; i++) {
                if ((stream.get(i + 2) & 0xFF) > 1) {
                    i += 2;
                    continue;
                }
                if (stream.get(i) == 0 && stream.get(i + 1) == 0 && stream.get(i + 2) == 1) {
                    return i;
                }
            }
            return -1;
        }
        return implementation.indexOfStartCode(stream, 0, stream.limit());
    }
}
