package com.github.auties00.parley.bytes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/// Checks every kernel implementation this JVM can run (the scalar one always, the vectorized one when the
/// `jdk.incubator.vector` module is resolved) against a byte-at-a-time reference, over heap, read-only and direct
/// buffers, every length around the vector widths, and unaligned offsets.
@DisplayName("ByteKernels")
class ByteKernelsTest {
    /// {@return the implementations to check}
    static List<ByteKernels> kernels() {
        var result = new ArrayList<ByteKernels>();
        result.add(ByteKernels.scalar());
        if (ModuleLayer.boot().findModule("jdk.incubator.vector").isPresent()) {
            var vector = VectorByteKernels.create();
            if (vector != null) {
                result.add(vector);
            }
        }
        return result;
    }

    /// {@return `bytes` in a heap, a read-only heap or a direct buffer positioned at `position`, with the bytes from
    /// there on}
    private static ByteBuffer buffer(byte[] bytes, int kind, int position) {
        var buffer = switch (kind) {
            case 0 -> ByteBuffer.wrap(bytes.clone());
            case 1 -> ByteBuffer.wrap(bytes.clone()).asReadOnlyBuffer();
            default -> ByteBuffer.allocateDirect(bytes.length).put(bytes).clear();
        };
        return buffer.position(position);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("kernels")
    @DisplayName("XORs arrays and buffers like the byte-at-a-time loop")
    void xor(ByteKernels kernels) {
        var random = new Random(1);
        for (var length = 0; length <= 200; length++) {
            for (var kind = 0; kind < 4; kind++) {
                var source = new byte[length + 9];
                random.nextBytes(source);
                var target = new byte[length + 5];
                random.nextBytes(target);
                var expected = target.clone();
                for (var i = 0; i < length; i++) {
                    expected[3 + i] ^= source[7 + i];
                }
                var actual = target.clone();
                if (kind == 3) {
                    kernels.xor(actual, 3, source, 7, length);
                } else {
                    kernels.xor(actual, 3, buffer(source, kind, 2), 7, length);
                }
                assertArrayEquals(expected, actual, "length " + length + ", kind " + kind);
            }
        }
    }

    /// {@return the index of the first start code by the definition}
    private static int reference(byte[] bytes, int from, int to) {
        for (var i = from; i + 2 < to; i++) {
            if (bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1) {
                return i;
            }
        }
        return -1;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("kernels")
    @DisplayName("finds the first start code like the definition, in streams dense with zeros and ones")
    void startCodes(ByteKernels kernels) {
        var random = new Random(2);
        for (var round = 0; round < 3000; round++) {
            var bytes = new byte[random.nextInt(300)];
            for (var i = 0; i < bytes.length; i++) {
                // Mostly 0, 1 and 2, so partial and complete start codes land at every lane position
                bytes[i] = (byte) (random.nextInt(8) < 6 ? random.nextInt(3) : random.nextInt(256));
            }
            var from = bytes.length == 0 ? 0 : random.nextInt(Math.min(bytes.length, 5) + 1);
            var to = Math.max(from, bytes.length - random.nextInt(Math.min(bytes.length, 5) + 1));
            var expected = reference(bytes, from, to);
            for (var kind = 0; kind < 3; kind++) {
                var buffer = buffer(bytes, kind, Math.min(from, 1));
                assertEquals(expected, kernels.indexOfStartCode(buffer, from, to),
                        "round " + round + ", kind " + kind);
                assertEquals(Math.min(from, 1), buffer.position(), "the position does not move");
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("kernels")
    @DisplayName("finds a start code past every vector boundary in a long run without one")
    void sparseStartCode(ByteKernels kernels) {
        for (var at = 0; at < 300; at++) {
            var bytes = new byte[320];
            java.util.Arrays.fill(bytes, (byte) 7);
            bytes[at] = 0;
            bytes[at + 1] = 0;
            bytes[at + 2] = 1;
            assertEquals(at, kernels.indexOfStartCode(ByteBuffer.wrap(bytes), 0, bytes.length));
            assertEquals(at, kernels.indexOfStartCode(buffer(bytes, 2, 0), 0, bytes.length));
            assertEquals(-1, kernels.indexOfStartCode(ByteBuffer.wrap(bytes), 0, at + 2));
        }
    }

    @Test
    @DisplayName("chooses the scalar kernels without the Vector API module or when the property disables it")
    void selection() {
        var chosen = ByteKernels.get();
        assertNotNull(chosen);
        var vectorPresent = ModuleLayer.boot().findModule("jdk.incubator.vector").isPresent();
        if (!vectorPresent || "false".equalsIgnoreCase(System.getProperty(ByteKernels.VECTOR_PROPERTY))) {
            assertSame(ByteKernels.scalar(), chosen);
        }
    }
}
