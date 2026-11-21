package com.github.auties00.parley.peer;

import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.SdpAttribute;
import com.github.auties00.parley.sdp.SdpLine;

import java.util.ArrayList;
import java.util.List;

/// Collects the lines of one media section in the order JSEP writes them.
final class SectionBuilder {
    /// The media type.
    private final String media;
    /// The port.
    private final int port;
    /// The transport protocol.
    private final String protocol;
    /// The formats.
    private final List<String> formats = new ArrayList<>();
    /// The lines after `m=`.
    private final List<SdpLine> lines = new ArrayList<>();

    SectionBuilder(String media, int port, String protocol) {
        this.media = media;
        this.port = port;
        this.protocol = protocol;
    }

    /// Appends a format.
    SectionBuilder format(String format) {
        formats.add(format);
        return this;
    }

    /// Appends formats.
    SectionBuilder formats(List<String> newFormats) {
        formats.addAll(newFormats);
        return this;
    }

    /// Appends a line.
    SectionBuilder line(SdpLine line) {
        lines.add(line);
        return this;
    }

    /// Appends an attribute.
    SectionBuilder attribute(SdpAttribute attribute) {
        lines.add(attribute.toLine());
        return this;
    }

    /// {@return the section}
    MediaDescription build() {
        return new MediaDescription(media, port, protocol, formats, lines);
    }
}
