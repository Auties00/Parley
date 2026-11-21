/// Provides the event streams of Parley's application-level objects: [EventStream], a bounded, blocking stream one
/// consumer reads with `for`, [EventStream#next()] or [EventStream#stream()], and [EventSource], the producing side a
/// component keeps private.
///
/// The peer connection, its tracks, DTMF senders and transports expose `events()` returning an [EventStream]. The
/// first stream opened on an object receives everything the object raised since it was created, so opening the
/// stream after the calls that raise the first events loses nothing; every stream is bounded and drops its oldest
/// events, counted, when its consumer falls behind.
///
/// Unless otherwise noted, passing `null` to a method or constructor of a type in this package throws
/// [NullPointerException].
package com.github.auties00.parley.event;
