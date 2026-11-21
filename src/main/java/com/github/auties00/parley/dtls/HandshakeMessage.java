package com.github.auties00.parley.dtls;

/// One complete handshake message: its type, its DTLS message sequence number and its body.
///
/// The two encodings differ in what enters the transcript: DTLS 1.2 hashes the 12-byte DTLS header (with the
/// sequence number and an unfragmented range), DTLS 1.3 the 4-byte TLS header.
///
/// ```text
/// DTLS header: type(1) || length(3) || message_seq(2) || fragment_offset(3) || fragment_length(3) || body
/// TLS header : type(1) || length(3) || body
/// ```
///
/// @param type       the handshake type
/// @param messageSeq the message sequence number
/// @param body       the body, not copied
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html#section-4.2.2 RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html#section-5.2 RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
record HandshakeMessage(int type, int messageSeq, byte[] body) {
    /// `hello_request`, which a DTLS 1.2 server sends to ask for a renegotiation.
    static final int HELLO_REQUEST = 0;

    /// `client_hello`.
    static final int CLIENT_HELLO = 1;

    /// `server_hello`, also the type of a DTLS 1.3 `HelloRetryRequest`.
    static final int SERVER_HELLO = 2;

    /// `hello_verify_request`, DTLS 1.2 only.
    static final int HELLO_VERIFY_REQUEST = 3;

    /// `new_session_ticket`.
    static final int NEW_SESSION_TICKET = 4;

    /// `encrypted_extensions`, DTLS 1.3 only.
    static final int ENCRYPTED_EXTENSIONS = 8;

    /// `certificate`.
    static final int CERTIFICATE = 11;

    /// `server_key_exchange`, DTLS 1.2 only.
    static final int SERVER_KEY_EXCHANGE = 12;

    /// `certificate_request`.
    static final int CERTIFICATE_REQUEST = 13;

    /// `server_hello_done`, DTLS 1.2 only.
    static final int SERVER_HELLO_DONE = 14;

    /// `certificate_verify`.
    static final int CERTIFICATE_VERIFY = 15;

    /// `client_key_exchange`, DTLS 1.2 only.
    static final int CLIENT_KEY_EXCHANGE = 16;

    /// `finished`.
    static final int FINISHED = 20;

    /// `key_update`, DTLS 1.3 only.
    static final int KEY_UPDATE = 24;

    /// `message_hash`, the synthetic message that replaces the first `ClientHello` in a DTLS 1.3 transcript after a
    /// `HelloRetryRequest`.
    static final int MESSAGE_HASH = 254;

    /// The length of the DTLS handshake header.
    static final int DTLS_HEADER_LENGTH = 12;

    /// {@return the message with its unfragmented 12-byte DTLS header}
    byte[] dtlsEncoding() {
        return new TlsWriter(DTLS_HEADER_LENGTH + body.length)
                .u8(type).u24(body.length).u16(messageSeq).u24(0).u24(body.length).bytes(body)
                .toByteArray();
    }

    /// {@return the message with its 4-byte TLS header}
    byte[] tlsEncoding() {
        return new TlsWriter(4 + body.length).u8(type).u24(body.length).bytes(body).toByteArray();
    }

    /// {@return the transcript encoding of the message in a version}
    ///
    /// @param version the negotiated version
    byte[] transcriptEncoding(DtlsVersion version) {
        return version == DtlsVersion.DTLS_1_3 ? tlsEncoding() : dtlsEncoding();
    }
}
