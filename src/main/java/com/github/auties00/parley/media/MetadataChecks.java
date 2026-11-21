package com.github.auties00.parley.media;

import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.OptionalLong;

/// The range checks the metadata records share.
final class MetadataChecks {
    private MetadataChecks() {
        throw new AssertionError("MetadataChecks cannot be instantiated");
    }

    /// Checks that an optional value is in `0..max`.
    ///
    /// @throws IllegalArgumentException if it is not
    static void checkRange(OptionalInt value, int max, String name) {
        Objects.requireNonNull(value, name + " cannot be null");
        if (value.isPresent()) {
            checkRange(value.getAsInt(), max, name);
        }
    }

    /// Checks that a value is in `0..max`.
    ///
    /// @throws IllegalArgumentException if it is not
    static void checkRange(int value, int max, String name) {
        if (value < 0 || value > max) {
            throw new IllegalArgumentException(name + " out of range 0.." + max + ": " + value);
        }
    }

    /// {@return the dependencies, copied, after checking each is a non-negative id below the frame id when known}
    ///
    /// @throws IllegalArgumentException if one is negative or not below the frame id
    static List<Long> checkDependencies(OptionalLong frameId, List<Long> dependencies) {
        Objects.requireNonNull(frameId, "frameId cannot be null");
        var copy = List.copyOf(dependencies);
        if (frameId.isPresent() && frameId.getAsLong() < 0) {
            throw new IllegalArgumentException("negative frame id: " + frameId.getAsLong());
        }
        for (var dependency : copy) {
            if (dependency < 0 || frameId.isPresent() && dependency >= frameId.getAsLong()) {
                throw new IllegalArgumentException("invalid dependency " + dependency + " of frame " + frameId);
            }
        }
        return copy;
    }
}
