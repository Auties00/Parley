package com.github.auties00.parley.stun;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Covers the `encodeTo` and `encodedLength` overloads that replaced the `Optional` parameters.
@DisplayName("StunMessage encoding overloads")
class StunEncodingOverloadsTest {
    @Test
    @DisplayName("write exactly what encode writes, signed or not, with or without FINGERPRINT")
    void overloads() throws Exception {
        var message = StunMessage.request(StunMethod.BINDING, List.of(new StunAttribute.Username("user:peer"),
                new StunAttribute.Priority(12345)));
        var key = StunKey.shortTerm("password");
        assertEquals(message.encode(false).remaining(), message.encodedLength());
        assertEquals(message.encode(true).remaining(), message.encodedLength(true));
        for (var integrity : StunIntegrity.values()) {
            for (var fingerprint : new boolean[]{false, true}) {
                var expected = message.encode(key, integrity, fingerprint);
                var length = message.encodedLength(integrity, fingerprint);
                assertEquals(expected.remaining(), length);
                var buffer = ByteBuffer.allocate(length + 4).position(4);
                assertEquals(length, message.encodeTo(buffer, key, integrity, fingerprint));
                assertEquals(expected, buffer.flip().position(4));
                assertTrue(StunMessage.decode(buffer.duplicate()).verifyIntegrity(key));
            }
        }
        var plain = ByteBuffer.allocate(message.encodedLength());
        message.encodeTo(plain);
        assertEquals(message.encode(false), plain.flip());
        var printed = ByteBuffer.allocate(message.encodedLength(true));
        message.encodeTo(printed, true);
        assertEquals(message.encode(true), printed.flip());
    }
}
