package com.github.auties00.parley.media;

/// The size of a video picture in pixels.
///
/// @param width  the width, positive
/// @param height the height, positive
public record Resolution(int width, int height) {
    /// Creates a resolution.
    ///
    /// @param width  the width
    /// @param height the height
    /// @throws IllegalArgumentException if `width` or `height` is not positive
    public Resolution {
        if (width <= 0 || height <= 0) {
            throw new IllegalArgumentException("resolution must be positive: " + width + "x" + height);
        }
    }

    /// {@return the resolution as `<width>x<height>`}
    @Override
    public String toString() {
        return width + "x" + height;
    }
}
