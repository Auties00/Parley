package com.github.auties00.parley.rtp.extension;

import com.github.auties00.parley.rtp.RtpPacket;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.TreeMap;

/// The negotiated mapping between RTP header extension element ids and extension URIs (`a=extmap`), plus whether
/// the one-byte and two-byte element forms may be mixed in a stream (`a=extmap-allow-mixed`).
///
/// Instances are immutable.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8285.html RFC 8285: A General Mechanism for RTP Header Extensions
public final class HeaderExtensionMap {
    private static final HeaderExtensionMap EMPTY = new HeaderExtensionMap(Map.of(), Map.of(), false);

    private final Map<Integer, URI> byId;
    private final Map<URI, Integer> byUri;
    private final boolean allowMixed;

    private HeaderExtensionMap(Map<Integer, URI> byId, Map<URI, Integer> byUri, boolean allowMixed) {
        this.byId = byId;
        this.byUri = byUri;
        this.allowMixed = allowMixed;
    }

    /// {@return a map that negotiated no extension}
    public static HeaderExtensionMap empty() {
        return EMPTY;
    }

    /// Creates a map from negotiated ids, without `a=extmap-allow-mixed`.
    ///
    /// @param idToUri the element id, `1..255`, of each negotiated URI
    /// @return the map
    /// @throws IllegalArgumentException if an id is out of range or two ids name the same URI
    public static HeaderExtensionMap of(Map<Integer, URI> idToUri) {
        Objects.requireNonNull(idToUri, "idToUri cannot be null");
        var byId = new TreeMap<Integer, URI>();
        var byUri = new HashMap<URI, Integer>();
        for (var entry : idToUri.entrySet()) {
            var id = Objects.requireNonNull(entry.getKey(), "id cannot be null");
            var uri = Objects.requireNonNull(entry.getValue(), "uri cannot be null");
            if (id < 1 || id > 255) {
                throw new IllegalArgumentException("extension id must be in 1..255: " + id);
            }
            if (byUri.put(uri, id) != null) {
                throw new IllegalArgumentException("two ids map to " + uri);
            }
            byId.put(id, uri);
        }
        return new HeaderExtensionMap(java.util.Collections.unmodifiableMap(byId), Map.copyOf(byUri), false);
    }

    /// {@return a copy of this map with `a=extmap-allow-mixed` set as given}
    ///
    /// @param allowMixed whether one-byte and two-byte elements may be mixed
    public HeaderExtensionMap withAllowMixed(boolean allowMixed) {
        return allowMixed == this.allowMixed ? this : new HeaderExtensionMap(byId, byUri, allowMixed);
    }

    /// {@return the id negotiated for a URI}
    ///
    /// @param uri the extension URI
    public OptionalInt idOf(URI uri) {
        Objects.requireNonNull(uri, "uri cannot be null");
        var id = byUri.get(uri);
        return id == null ? OptionalInt.empty() : OptionalInt.of(id);
    }

    /// {@return the URI negotiated for an id}
    ///
    /// @param id the element id
    public Optional<URI> uriOf(int id) {
        return Optional.ofNullable(byId.get(id));
    }

    /// {@return whether a URI was negotiated}
    ///
    /// @param uri the extension URI
    public boolean contains(URI uri) {
        return byUri.containsKey(Objects.requireNonNull(uri, "uri cannot be null"));
    }

    /// {@return whether one-byte and two-byte elements may be mixed, `a=extmap-allow-mixed`}
    public boolean allowMixed() {
        return allowMixed;
    }

    /// {@return the unmodifiable id to URI mapping, ordered by id}
    public Map<Integer, URI> entries() {
        return byId;
    }

    /// {@return the raw value of the element a packet carries for a URI, a read-only slice of the packet}
    ///
    /// @param packet the packet
    /// @param uri    the extension URI
    public Optional<java.nio.ByteBuffer> find(RtpPacket packet, URI uri) {
        Objects.requireNonNull(packet, "packet cannot be null");
        var id = byUri.get(Objects.requireNonNull(uri, "uri cannot be null"));
        return id == null ? Optional.empty() : packet.extension(id);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof HeaderExtensionMap that && byId.equals(that.byId) && allowMixed == that.allowMixed;
    }

    @Override
    public int hashCode() {
        return byId.hashCode() * 31 + Boolean.hashCode(allowMixed);
    }

    @Override
    public String toString() {
        return "HeaderExtensionMap" + byId + (allowMixed ? "[allow-mixed]" : "");
    }
}
