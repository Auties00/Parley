/// Provides the repair payload formats of RTP: retransmission ([Rtx]), redundant audio ([Red], [RedEncoder]) and
/// forward error correction in the ULPFEC and FlexFEC formats ([FecEncoder], [FecDecoder], [FecFormat]).
///
/// The package is internal to Parley: the send and receive streams of the `rtp.session` package apply these formats
/// as negotiated, and the module does not export it.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc4588.html RFC 4588: RTP Retransmission Payload Format
/// @spec https://www.rfc-editor.org/rfc/rfc2198.html RFC 2198: RTP Payload for Redundant Audio Data
/// @spec https://www.rfc-editor.org/rfc/rfc5109.html RFC 5109: RTP Payload Format for Generic Forward Error Correction
/// @spec https://www.rfc-editor.org/rfc/rfc8627.html RFC 8627: RTP Payload Format for Flexible Forward Error Correction (FEC)
package com.github.auties00.parley.rtp.fec;
