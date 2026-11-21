package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;

/// A transformation of encoded frames between the application and the network, the W3C encoded transform.
///
/// On a sender it runs on every frame after the application writes it and before packetization; on a receiver it runs
/// on every assembled frame before the application reads it. End-to-end encryption such as SFrame is its typical use:
/// the sender's transform encrypts the payload and the receiver's decrypts it, while RTP headers stay readable for
/// SFUs.
///
/// {@snippet lang = java :
/// sender.setTransform(frame -> frame.withData(sframe.encrypt(frame.data())));
/// receiver.setTransform(frame -> frame.withData(sframe.decrypt(frame.data())));
/// }
///
/// A transform runs on the thread that writes or assembles the frame, so it must not block for long. One that throws
/// drops the frame.
///
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
@FunctionalInterface
public interface FrameTransform {
    /// {@return the transformed frame}
    ///
    /// @param frame the frame
    EncodedFrame apply(EncodedFrame frame);
}
