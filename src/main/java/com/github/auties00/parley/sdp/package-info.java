/// Provides the session description model of RFC 8866: [SessionDescription] and its [MediaDescription]s, made of
/// [SdpLine]s, together with the two attribute families a media transport reads from them, the RTP payload formats
/// ([RtpCodec], RFC 8866 sections 6.6 and 6.15) and the SDES keys ([SdesCrypto], RFC 4568).
///
/// The model is a lossless view of the text: a parsed description keeps every line, in order and verbatim, so the
/// attributes this package does not interpret survive a parse and encode round trip. Every type is immutable.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
package com.github.auties00.parley.sdp;
