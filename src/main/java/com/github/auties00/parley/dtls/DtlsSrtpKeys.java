package com.github.auties00.parley.dtls;

import java.util.Objects;

/// The SRTP master keys a DTLS-SRTP handshake exported, already assigned to the local and the remote direction.
///
/// The exporter output, `client_key || server_key || client_salt || server_salt` (RFC 5764 section 4.2), is split by
/// role: the DTLS client protects its media with the client key and salt and the server with the server ones. The
/// local pair keys an SRTP context that protects outgoing packets and the remote pair one that unprotects incoming
/// packets, both with [SrtpProfile#suite()] of [#profile()].
///
/// The key material is secret: the record copies it in and out, and [#toString()] leaves it out.
///
/// @param profile    the negotiated protection profile
/// @param localKey   the master key of the media this endpoint sends
/// @param localSalt  the master salt of the media this endpoint sends
/// @param remoteKey  the master key of the media the peer sends
/// @param remoteSalt the master salt of the media the peer sends
/// @spec https://www.rfc-editor.org/rfc/rfc5764.html RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
public record DtlsSrtpKeys(SrtpProfile profile, byte[] localKey, byte[] localSalt, byte[] remoteKey, byte[] remoteSalt) {
    /// Creates the keys, copying them.
    ///
    /// @param profile    the negotiated protection profile
    /// @param localKey   the master key of the media this endpoint sends
    /// @param localSalt  the master salt of the media this endpoint sends
    /// @param remoteKey  the master key of the media the peer sends
    /// @param remoteSalt the master salt of the media the peer sends
    public DtlsSrtpKeys {
        Objects.requireNonNull(profile, "profile cannot be null");
        localKey = localKey.clone();
        localSalt = localSalt.clone();
        remoteKey = remoteKey.clone();
        remoteSalt = remoteSalt.clone();
    }

    /// {@return a copy of the master key of the media this endpoint sends}
    @Override
    public byte[] localKey() {
        return localKey.clone();
    }

    /// {@return a copy of the master salt of the media this endpoint sends}
    @Override
    public byte[] localSalt() {
        return localSalt.clone();
    }

    /// {@return a copy of the master key of the media the peer sends}
    @Override
    public byte[] remoteKey() {
        return remoteKey.clone();
    }

    /// {@return a copy of the master salt of the media the peer sends}
    @Override
    public byte[] remoteSalt() {
        return remoteSalt.clone();
    }

    /// {@return the profile, without the key material}
    @Override
    public String toString() {
        return "DtlsSrtpKeys[profile=" + profile + "]";
    }
}
