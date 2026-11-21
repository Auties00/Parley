package com.github.auties00.parley.rtp.session;

import com.github.auties00.parley.rtp.extension.HeaderExtensionMap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/// The routing of a BUNDLE group's incoming RTP, as the latest offer/answer exchange negotiated it: the header
/// extension ids that carry MID and RID, and the route to each receive stream.
///
/// @param extensions the header extension ids of the BUNDLE group
/// @param routes     the routes, one per receive stream
/// @spec https://www.rfc-editor.org/rfc/rfc8843.html RFC 8843: Negotiating Media Multiplexing Using the Session Description Protocol (SDP)
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
public record RtpRoutingTable(HeaderExtensionMap extensions, List<RtpDemuxer.Route<RtpReceiveStream>> routes) {
    /// Checks the fields and copies `routes`.
    public RtpRoutingTable {
        Objects.requireNonNull(extensions, "extensions cannot be null");
        routes = List.copyOf(routes);
    }

    /// {@return a table routing to receive streams by what their configurations signal: MID, RID, SSRCs and payload
    /// types}
    ///
    /// @param extensions the header extension ids of the BUNDLE group
    /// @param streams    the receive streams
    public static RtpRoutingTable of(HeaderExtensionMap extensions, Collection<RtpReceiveStream> streams) {
        var routes = new ArrayList<RtpDemuxer.Route<RtpReceiveStream>>(streams.size());
        for (var stream : streams) {
            routes.add(stream.route());
        }
        return new RtpRoutingTable(extensions, routes);
    }
}
