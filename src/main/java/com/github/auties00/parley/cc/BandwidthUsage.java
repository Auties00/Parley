package com.github.auties00.parley.cc;

/// The state of the delay-based overuse detector, the signal that drives the rate controller.
///
/// @spec https://datatracker.ietf.org/doc/html/draft-ietf-rmcat-gcc-02 A Google Congestion Control Algorithm for Real-Time Communication
enum BandwidthUsage {
    /// The one-way delay gradient is within the adaptive threshold.
    NORMAL,
    /// The delay gradient is above the threshold: queues are building up.
    OVERUSING,
    /// The delay gradient is below the negative threshold: queues are draining.
    UNDERUSING
}
