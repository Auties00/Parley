package com.github.auties00.parley.stun;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReferenceArray;

/// Hands out keyed HMAC instances for message integrity without a provider lookup and a key schedule per message.
///
/// A few recently used keys keep an initialized prototype each; a request for one of them gets a clone of its
/// prototype, which copies the inner and outer hash states the key produced. An ICE agent signs with the remote
/// password and verifies with its own, so the slots hold the handful of keys a connection alternates between; a miss
/// builds a new prototype in the slot the key hashes to.
///
/// # Threading
///
/// Safe for concurrent use: slots are replaced atomically and a prototype is only ever cloned, never used.
final class StunMacs {
    /// The number of cached keys, a power of two.
    private static final int SLOTS = 16;

    /// A cached key with its initialized prototype.
    ///
    /// @param algorithm the JCA name of the HMAC
    /// @param key       the key bytes, owned by the slot
    /// @param prototype the HMAC initialized with the key, never updated
    private record Slot(String algorithm, byte[] key, Mac prototype) {
    }

    /// The slots, indexed by the key's hash.
    private static final AtomicReferenceArray<Slot> CACHE = new AtomicReferenceArray<>(SLOTS);

    private StunMacs() {
        throw new AssertionError("StunMacs cannot be instantiated");
    }

    /// {@return an HMAC of `algorithm` keyed with `key`, owned by the caller}
    ///
    /// @param algorithm the JCA name, `HmacSHA1` or `HmacSHA256`
    /// @param key       the key bytes, not retained beyond the cache's own copy
    static Mac get(String algorithm, byte[] key) {
        var index = (Arrays.hashCode(key) * 31 + algorithm.hashCode()) & (SLOTS - 1);
        var slot = CACHE.get(index);
        if (slot != null && slot.algorithm().equals(algorithm) && Arrays.equals(slot.key(), key)) {
            try {
                return (Mac) slot.prototype().clone();
            } catch (CloneNotSupportedException exception) {
                return create(algorithm, key);
            }
        }
        var prototype = create(algorithm, key);
        try {
            var copy = (Mac) prototype.clone();
            CACHE.set(index, new Slot(algorithm, key.clone(), prototype));
            return copy;
        } catch (CloneNotSupportedException exception) {
            return prototype;
        }
    }

    /// {@return a new HMAC of `algorithm` keyed with `key`}
    private static Mac create(String algorithm, byte[] key) {
        try {
            var mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException(algorithm + " unavailable", exception);
        }
    }
}
