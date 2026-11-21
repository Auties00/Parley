package com.github.auties00.parley.cc;

import java.util.Objects;
import java.util.Optional;

/// Identifies one encoding a [BitrateAllocator] allocates to: a sender and, for a simulcast sender, the RID of one
/// of its encodings.
///
/// @param senderId an application-chosen id of the sender, such as its track id or MID
/// @param rid      the RTP stream id of the encoding, empty for a sender with a single encoding
public record AllocationKey(String senderId, Optional<String> rid) {
    /// Validates the key.
    public AllocationKey {
        Objects.requireNonNull(senderId, "senderId");
        Objects.requireNonNull(rid, "rid");
    }

    /// {@return the key of a sender with a single encoding}
    ///
    /// @param senderId the sender id
    public static AllocationKey of(String senderId) {
        return new AllocationKey(senderId, Optional.empty());
    }

    /// {@return the key of one simulcast encoding}
    ///
    /// @param senderId the sender id
    /// @param rid      the RTP stream id
    public static AllocationKey of(String senderId, String rid) {
        return new AllocationKey(senderId, Optional.of(rid));
    }
}
