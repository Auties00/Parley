package com.github.auties00.parley.rtp;

/// Encodes and decodes G.711 audio, the `PCMA` (A-law) and `PCMU` (mu-law) payload formats of RFC 3551: one byte
/// per 8 kHz sample, static payload types `8` and `0`.
///
/// The companding follows ITU-T G.711 with the bit inversions of its reference implementation: A-law XORs every code
/// with `0x55`, mu-law complements it, so silence encodes as `0xD5` and `0xFF`. The class is stateless and its
/// methods are safe for concurrent use.
///
/// @spec https://www.itu.int/rec/T-REC-G.711 ITU-T G.711: Pulse code modulation (PCM) of voice frequencies
/// @spec https://www.rfc-editor.org/rfc/rfc3551.html RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
public final class G711 {
    /// The mu-law bias added to a magnitude before the segment search.
    private static final int MU_LAW_BIAS = 0x84;

    /// The largest magnitude mu-law encodes; louder samples are clipped to it.
    private static final int MU_LAW_CLIP = 32635;

    private G711() {
        throw new AssertionError("G711 cannot be instantiated");
    }

    /// {@return one A-law byte for each of the first `length` samples of `pcm`}
    ///
    /// @param pcm    the 16-bit signed samples
    /// @param length the number of samples to encode
    /// @throws ArrayIndexOutOfBoundsException if `length` exceeds `pcm.length`
    /// @throws NegativeArraySizeException if `length` is negative
    public static byte[] encodeALaw(short[] pcm, int length) {
        var out = new byte[length];
        for (var i = 0; i < length; i++) {
            out[i] = linearToALaw(pcm[i]);
        }
        return out;
    }

    /// {@return one 16-bit signed sample for each A-law byte of `data`}
    ///
    /// @param data the A-law bytes
    public static short[] decodeALaw(byte[] data) {
        var out = new short[data.length];
        for (var i = 0; i < data.length; i++) {
            out[i] = aLawToLinear(data[i]);
        }
        return out;
    }

    /// {@return one mu-law byte for each of the first `length` samples of `pcm`}
    ///
    /// @param pcm    the 16-bit signed samples
    /// @param length the number of samples to encode
    /// @throws ArrayIndexOutOfBoundsException if `length` exceeds `pcm.length`
    /// @throws NegativeArraySizeException if `length` is negative
    public static byte[] encodeMuLaw(short[] pcm, int length) {
        var out = new byte[length];
        for (var i = 0; i < length; i++) {
            out[i] = linearToMuLaw(pcm[i]);
        }
        return out;
    }

    /// {@return one 16-bit signed sample for each mu-law byte of `data`}
    ///
    /// @param data the mu-law bytes
    public static short[] decodeMuLaw(byte[] data) {
        var out = new short[data.length];
        for (var i = 0; i < data.length; i++) {
            out[i] = muLawToLinear(data[i]);
        }
        return out;
    }

    /// {@return the A-law code of one sample}
    static byte linearToALaw(short sample) {
        var pcm = sample >> 3;
        int mask;
        if (pcm >= 0) {
            mask = 0xD5;
        } else {
            mask = 0x55;
            pcm = -pcm - 1;
        }
        var segment = 0;
        var limit = 0x1F;
        while (segment < 8 && pcm > limit) {
            segment++;
            limit = (limit << 1) | 1;
        }
        if (segment >= 8) {
            return (byte) (0x7F ^ mask);
        }
        var code = segment << 4;
        code |= segment < 2 ? (pcm >> 1) & 0x0F : (pcm >> segment) & 0x0F;
        return (byte) (code ^ mask);
    }

    /// {@return the sample one A-law code decodes to}
    static short aLawToLinear(byte code) {
        var value = (code ^ 0x55) & 0xFF;
        var magnitude = (value & 0x0F) << 4;
        var segment = (value & 0x70) >> 4;
        magnitude = switch (segment) {
            case 0 -> magnitude + 8;
            case 1 -> magnitude + 0x108;
            default -> (magnitude + 0x108) << (segment - 1);
        };
        return (short) ((value & 0x80) != 0 ? magnitude : -magnitude);
    }

    /// {@return the mu-law code of one sample}
    static byte linearToMuLaw(short sample) {
        var pcm = sample;
        var sign = (pcm >> 8) & 0x80;
        int magnitude = sign != 0 ? -pcm : pcm;
        if (magnitude > MU_LAW_CLIP) {
            magnitude = MU_LAW_CLIP;
        }
        magnitude += MU_LAW_BIAS;
        var exponent = 7;
        for (var mask = 0x4000; (magnitude & mask) == 0 && exponent > 0; mask >>= 1) {
            exponent--;
        }
        var mantissa = (magnitude >> (exponent + 3)) & 0x0F;
        return (byte) ~(sign | (exponent << 4) | mantissa);
    }

    /// {@return the sample one mu-law code decodes to}
    static short muLawToLinear(byte code) {
        var value = ~code & 0xFF;
        var magnitude = (((value & 0x0F) << 3) + MU_LAW_BIAS) << ((value & 0x70) >> 4);
        return (short) ((value & 0x80) != 0 ? MU_LAW_BIAS - magnitude : magnitude - MU_LAW_BIAS);
    }
}
