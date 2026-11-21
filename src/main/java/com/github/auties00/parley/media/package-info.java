/// Describes media independently of how it travels: the kind of a track ([MediaKind]), a codec and its format
/// parameters ([Codec], [RtpCodecParameters], [RtcpFeedback]), and the unit the application exchanges with Parley,
/// an encoded frame ([EncodedFrame]) with its per-format [FrameMetadata].
///
/// Parley never encodes or decodes: an application sends frames its own encoder produced and receives frames it
/// hands to its own decoder. The types here are immutable values, safe to share between threads.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
///
/// @spec https://www.rfc-editor.org/rfc/rfc8866.html RFC 8866: SDP: Session Description Protocol
/// @spec https://www.rfc-editor.org/rfc/rfc4855.html RFC 4855: Media Type Registration of RTP Payload Formats
package com.github.auties00.parley.media;
