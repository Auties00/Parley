package com.github.auties00.parley.dtls;

import java.io.IOException;

/// Carries the DTLS datagrams of one association between a [DtlsEndpoint] and the socket it runs over.
///
/// The owner of the socket implements it: it sends datagrams to the peer, and it demultiplexes DTLS from the other
/// protocols sharing the socket (a first byte in `20..63`, RFC 7983) and hands only DTLS datagrams to
/// [#receive(long)]. During [DtlsEndpoint#handshake(java.time.Duration)] the endpoint calls [#receive(long)] from
/// the handshaking thread only; it calls [#send(byte\[\])] from that thread and, after the handshake, from whichever
/// thread calls [DtlsEndpoint#handleAfterHandshake(byte\[\])] or [DtlsEndpoint#close()], one call at a time.
///
/// @spec https://www.rfc-editor.org/rfc/rfc7983.html RFC 7983: Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)
public interface DtlsDatagramIo {
    /// Sends one datagram to the peer.
    ///
    /// @param datagram the datagram, at most 1200 bytes; the implementation may keep it
    /// @throws IOException if the socket cannot send
    void send(byte[] datagram) throws IOException;

    /// Waits for the next DTLS datagram from the peer.
    ///
    /// @param timeoutNanos the longest time to wait, in nanoseconds, always positive
    /// @return the datagram, which the endpoint keeps, or `null` if none arrived in time
    /// @throws IOException          if the socket fails; the handshake fails with a [DtlsException]
    /// @throws InterruptedException if the calling thread is interrupted
    byte[] receive(long timeoutNanos) throws IOException, InterruptedException;
}
