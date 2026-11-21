package com.github.auties00.parley.dtls;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/// The handshake messages a `Finished` value, a signature and the key schedule cover, in order.
///
/// Messages are kept as they are until the version is known, because DTLS 1.2 and DTLS 1.3 hash different encodings
/// of the same `ClientHello` (see [HandshakeMessage]). After a DTLS 1.3 `HelloRetryRequest` the first `ClientHello` is
/// replaced by the synthetic `message_hash` message.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8446.html RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
/// @spec https://www.rfc-editor.org/rfc/rfc5246.html RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
final class Transcript {
    /// The messages, in order.
    private final List<HandshakeMessage> messages = new ArrayList<>();

    /// The encoded `message_hash` that stands for the messages before a `HelloRetryRequest`, or `null`.
    private byte[] syntheticPrefix;

    /// Appends a message.
    ///
    /// @param message the message
    void add(HandshakeMessage message) {
        messages.add(message);
    }

    /// Removes every message, for a DTLS 1.2 `ClientHello` sent again after a `HelloVerifyRequest`, which restarts the
    /// transcript.
    void clear() {
        messages.clear();
        syntheticPrefix = null;
    }

    /// Replaces the messages so far, the first `ClientHello`, with the `message_hash` message of DTLS 1.3.
    ///
    /// @param hash the hash of the negotiated suite
    void replaceWithMessageHash(HashAlgorithm hash) {
        var digest = hash.hash(bytes(DtlsVersion.DTLS_1_3));
        syntheticPrefix = new HandshakeMessage(HandshakeMessage.MESSAGE_HASH, 0, digest).tlsEncoding();
        messages.clear();
    }

    /// {@return the concatenated encodings of the messages in a version}
    ///
    /// @param version the version whose encoding to use
    byte[] bytes(DtlsVersion version) {
        var out = new ByteArrayOutputStream();
        if (syntheticPrefix != null) {
            out.writeBytes(syntheticPrefix);
        }
        for (var message : messages) {
            out.writeBytes(message.transcriptEncoding(version));
        }
        return out.toByteArray();
    }

    /// {@return the hash of the messages in a version}
    ///
    /// @param version the version whose encoding to use
    /// @param hash    the hash
    byte[] hash(DtlsVersion version, HashAlgorithm hash) {
        return hash.hash(bytes(version));
    }
}
