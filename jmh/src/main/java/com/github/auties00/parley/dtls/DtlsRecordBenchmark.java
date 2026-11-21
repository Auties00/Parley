package com.github.auties00.parley.dtls;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/// DTLS 1.2 AES-128-GCM application data records of 1,000 bytes (an SCTP data chunk): sealing and opening.
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgsAppend = {"--add-modules=jdk.incubator.vector"})
public class DtlsRecordBenchmark {
    private RecordLayer writer;
    private RecordLayer reader;
    private byte[] payload;

    @Setup
    public void setup() {
        writer = new RecordLayer();
        reader = new RecordLayer();
        writer.setVersion(DtlsVersion.DTLS_1_2);
        reader.setVersion(DtlsVersion.DTLS_1_2);
        var key = new byte[16];
        new Random(1).nextBytes(key);
        writer.installWrite(1, new Dtls12RecordCipher(Aead.AES_128_GCM, key, new byte[4]));
        reader.installRead(1, new Dtls12RecordCipher(Aead.AES_128_GCM, key, new byte[4]));
        payload = new byte[1000];
        new Random(2).nextBytes(payload);
    }

    /// Seals one record.
    @Benchmark
    public byte[] encrypt() throws DtlsException {
        return writer.encode(RecordLayer.APPLICATION_DATA, 1, payload, 0xFEFD).bytes();
    }

    /// Seals one record and opens it.
    @Benchmark
    public void encryptDecrypt(Blackhole blackhole) throws IOException {
        var sealed = writer.encode(RecordLayer.APPLICATION_DATA, 1, payload, 0xFEFD).bytes();
        reader.decode(sealed, blackhole::consume);
    }
}
