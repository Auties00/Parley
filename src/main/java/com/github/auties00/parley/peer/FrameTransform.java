package com.github.auties00.parley.peer;

import com.github.auties00.parley.media.EncodedFrame;

import java.util.function.Consumer;

/// A transformation of encoded frames between the application and the network, the W3C encoded transform.
///
/// On a sender it runs on every frame after the application writes it and before packetization; on a receiver it runs
/// on every assembled frame before the application reads it. End-to-end encryption such as SFrame is its typical use:
/// the sender's transform encrypts the payload and the receiver's decrypts it, while RTP headers stay readable for
/// SFUs.
///
/// {@snippet lang = java :
/// sender.setTransform((frame, output) -> output.accept(frame.withData(sframe.encrypt(frame.data()))));
/// receiver.setTransform((frame, output) -> sframe.tryDecrypt(frame.data())
///         .ifPresent(data -> output.accept(frame.withData(data))));   // a frame that fails to decrypt is dropped
/// }
///
/// @spec https://www.w3.org/TR/webrtc-encoded-transform/ WebRTC Encoded Transform
@FunctionalInterface
public interface FrameTransform {
    /// Transforms one frame, handing the result to `output`.
    ///
    /// The transform may call `output` zero times (dropping the frame), once, or several times, and may call it
    /// from any thread, now or later; calls after the sender or receiver stopped are ignored. The transform itself
    /// runs on the thread that writes or assembles the frame, so it must not block for long. A transform that throws
    /// drops the frame, which the sender or receiver counts in its `transformFailures()`.
    ///
    /// @param frame  the frame
    /// @param output where the transformed frames go
    void transform(EncodedFrame frame, Consumer<? super EncodedFrame> output);
}
