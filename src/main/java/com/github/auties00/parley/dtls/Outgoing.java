package com.github.auties00.parley.dtls;

/// One element of a flight the connection sends and retransmits.
sealed interface Outgoing {
    /// {@return the epoch the element is sent in}
    long epoch();

    /// A handshake message, fragmented to fit the path.
    ///
    /// @param message the message
    /// @param epoch   the epoch
    record Message(HandshakeMessage message, long epoch) implements Outgoing {
    }

    /// A record sent as it is: a `ChangeCipherSpec`, or a `HelloVerifyRequest` with its DTLS 1.0 record version.
    ///
    /// @param contentType   the content type
    /// @param epoch         the epoch
    /// @param payload       the record payload
    /// @param recordVersion the record header version
    record Record(int contentType, long epoch, byte[] payload, int recordVersion) implements Outgoing {
        /// Creates a record with the DTLS 1.2 record version.
        ///
        /// @param contentType the content type
        /// @param epoch       the epoch
        /// @param payload     the record payload
        Record(int contentType, long epoch, byte[] payload) {
            this(contentType, epoch, payload, DtlsVersion.DTLS_1_2.wireValue());
        }
    }
}
