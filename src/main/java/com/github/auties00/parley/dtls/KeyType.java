package com.github.auties00.parley.dtls;

import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

/// The kinds of certificate key a handshake signs with, which decide the DTLS 1.2 cipher suite and the signature
/// schemes that apply.
enum KeyType {
    /// An elliptic curve key, signing with ECDSA.
    EC,

    /// An RSA key, signing with PKCS #1 v1.5 or PSS.
    RSA,

    /// An Ed25519 key; accepted from peers, never generated.
    ED25519;

    /// {@return the kind of a public key}
    ///
    /// @param key the key
    /// @throws IllegalArgumentException if the key is of another kind
    static KeyType of(PublicKey key) {
        if (key instanceof ECKey) {
            return EC;
        }
        if (key instanceof RSAKey) {
            return RSA;
        }
        if (key.getAlgorithm().equalsIgnoreCase("Ed25519") || key.getAlgorithm().equalsIgnoreCase("EdDSA")) {
            return ED25519;
        }
        throw new IllegalArgumentException("unsupported key algorithm " + key.getAlgorithm());
    }
}
