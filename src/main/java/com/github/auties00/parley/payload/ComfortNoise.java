package com.github.auties00.parley.payload;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/// One comfort noise payload of RFC 3389: the level of the background noise and, optionally, its spectral shape as
/// quantized reflection coefficients.
///
/// ```text
///  0                   1                   2
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0|   level     |      N1       |      N2       | ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// @param noiseLevel             the noise level in -dBov, `0..127`
/// @param reflectionCoefficients the quantized reflection coefficients, each `0..255`, in order; empty for a
///                               level-only payload; unmodifiable
/// @spec https://www.rfc-editor.org/rfc/rfc3389.html RFC 3389: Real-time Transport Protocol (RTP) Payload for Comfort Noise (CN)
public record ComfortNoise(int noiseLevel, List<Integer> reflectionCoefficients) {
    /// Creates a payload.
    ///
    /// @param noiseLevel             the noise level
    /// @param reflectionCoefficients the coefficients, copied
    /// @throws IllegalArgumentException if a value is outside its range
    public ComfortNoise {
        if (noiseLevel < 0 || noiseLevel > 127) {
            throw new IllegalArgumentException("noise level out of range: " + noiseLevel);
        }
        reflectionCoefficients = List.copyOf(reflectionCoefficients);
        for (var coefficient : reflectionCoefficients) {
            if (coefficient < 0 || coefficient > 255) {
                throw new IllegalArgumentException("reflection coefficient out of range: " + coefficient);
            }
        }
    }

    /// Parses a payload.
    ///
    /// @param payload the payload, from position to limit; its position does not change
    /// @return the comfort noise
    /// @throws PayloadFormatException if the payload is empty or its reserved bit is set
    public static ComfortNoise parse(ByteBuffer payload) throws PayloadFormatException {
        if (!payload.hasRemaining()) {
            throw new PayloadFormatException("empty comfort noise payload");
        }
        var first = Payloads.u8(payload, payload.position());
        if ((first & 0x80) != 0) {
            throw new PayloadFormatException("comfort noise reserved bit set");
        }
        var coefficients = new ArrayList<Integer>(payload.remaining() - 1);
        for (var i = payload.position() + 1; i < payload.limit(); i++) {
            coefficients.add(Payloads.u8(payload, i));
        }
        return new ComfortNoise(first, coefficients);
    }

    /// {@return the payload, a new buffer positioned at zero}
    public ByteBuffer toBuffer() {
        var buffer = ByteBuffer.allocate(1 + reflectionCoefficients.size());
        buffer.put((byte) noiseLevel);
        for (var coefficient : reflectionCoefficients) {
            buffer.put((byte) (int) coefficient);
        }
        return buffer.flip();
    }
}
