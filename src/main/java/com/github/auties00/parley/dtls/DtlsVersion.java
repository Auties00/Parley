package com.github.auties00.parley.dtls;

import java.util.Optional;

/// The DTLS protocol versions this library negotiates.
///
/// A client offering both versions sends a DTLS 1.2 compatible `ClientHello` with the `supported_versions` extension,
/// so a DTLS 1.2-only server still completes the handshake; a server supporting both picks DTLS 1.3 whenever the client
/// offers it and marks a DTLS 1.2 `ServerHello` with the downgrade sentinel otherwise.
///
/// @spec https://www.rfc-editor.org/rfc/rfc6347.html RFC 6347: Datagram Transport Layer Security Version 1.2
/// @spec https://www.rfc-editor.org/rfc/rfc9147.html RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
public enum DtlsVersion {
    /// DTLS 1.2, wire value `0xFEFD`.
    DTLS_1_2(0xFEFD),

    /// DTLS 1.3, wire value `0xFEFC`.
    DTLS_1_3(0xFEFC);

    /// The wire value.
    private final int wireValue;

    /// Creates a version constant.
    DtlsVersion(int wireValue) {
        this.wireValue = wireValue;
    }

    /// {@return the version with a wire value, or an empty optional for any other version}
    ///
    /// @param wireValue the 16-bit value
    public static Optional<DtlsVersion> ofWireValue(int wireValue) {
        for (var version : values()) {
            if (version.wireValue == wireValue) {
                return Optional.of(version);
            }
        }
        return Optional.empty();
    }

    /// {@return the 16-bit value that names the version on the wire}
    public int wireValue() {
        return wireValue;
    }
}
