package com.github.auties00.parley.rtp.fec;

/// The two mask designs a mask [FecEncoder] chooses between, after the loss pattern the receiver reports.
public enum FecMaskType {
    /// Masks against losses that come one at a time: interleaved sets overlapped with contiguous blocks, so most
    /// packets are protected by two repair packets.
    RANDOM,
    /// Masks against losses that come in runs: purely interleaved sets, so consecutive packets are protected by
    /// different repair packets.
    BURSTY
}
