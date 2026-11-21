package com.github.auties00.parley.peer;

import com.github.auties00.parley.sdp.MediaDescription;
import com.github.auties00.parley.sdp.SdpLine;
import com.github.auties00.parley.sdp.SessionDescription;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/// The edits an application may make to a description between `createOffer` or `createAnswer` and
/// `setLocalDescription`.
///
/// Allowed: removing and reordering payload formats (with their `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` lines), editing
/// `a=fmtp` and `a=rtcp-fb` lines, adding, editing and removing `b=` lines, removing `a=extmap` lines, and removing the
/// `a=rid` and `a=simulcast` lines of simulcast. Everything else must be unchanged, character for character.
///
/// @implNote This implementation accepts the edits RFC 9429 section 5.4 permits plus those every browser tolerates
/// and applications rely on (codec filtering, bandwidth caps, simulcast removal); a payload format may not be remapped
/// to another encoding, and a removed line may not be replaced by a new one of another kind.
/// @spec https://www.rfc-editor.org/rfc/rfc9429.html RFC 9429: JavaScript Session Establishment Protocol (JSEP)
final class SdpMungingRules {
    /// The attributes whose lines may be removed.
    private static final Set<String> REMOVABLE = Set.of("rtpmap", "fmtp", "rtcp-fb", "extmap", "rid", "simulcast");
    /// The attributes whose values may change.
    private static final Set<String> EDITABLE = Set.of("fmtp", "rtcp-fb");

    private SdpMungingRules() {
    }

    /// Checks that `applied` differs from `created` only by allowed edits.
    ///
    /// @throws InvalidModificationException if it does not
    static void check(SessionDescription created, SessionDescription applied) {
        compareLines("the session level", created.lines(), applied.lines(), true);
        if (created.media().size() != applied.media().size()) {
            throw new InvalidModificationException("media sections cannot be added or removed");
        }
        for (var index = 0; index < created.media().size(); index++) {
            checkSection(index, created.media().get(index), applied.media().get(index));
        }
    }

    /// Checks one media section.
    private static void checkSection(int index, MediaDescription created, MediaDescription applied) {
        var where = "media section " + index;
        if (!created.media().equals(applied.media()) || created.port() != applied.port()
                || !created.protocol().equals(applied.protocol())) {
            throw new InvalidModificationException(where + ": the m= line media, port or protocol changed");
        }
        if (!created.formats().containsAll(applied.formats())
                || applied.formats().size() != new HashSet<>(applied.formats()).size()) {
            throw new InvalidModificationException(where + ": formats can only be removed or reordered");
        }
        if (applied.formats().isEmpty() && created.port() != 0) {
            throw new InvalidModificationException(where + ": every format was removed");
        }
        compareLines(where, created.lines(), applied.lines(), false);
        var kept = new HashSet<>(applied.formats());
        for (var line : applied.lines()) {
            if (line.type() != 'a') {
                continue;
            }
            var name = line.attributeName();
            if (!REMOVABLE.contains(name)) {
                continue;
            }
            if (!EDITABLE.contains(name) && !created.lines().contains(line)) {
                throw new InvalidModificationException(where + ": a=" + name + " lines cannot be added or edited");
            }
            if (name.equals("rtpmap") || name.equals("fmtp") || name.equals("rtcp-fb")) {
                var format = line.attributeValue().orElse("").strip().split(" ", 2)[0];
                if (!format.equals("*") && !kept.contains(format)) {
                    throw new InvalidModificationException(where + ": a=" + name + " for a removed format " + format);
                }
            }
        }
        for (var format : applied.formats()) {
            var createdRtpmap = rtpmap(created, format);
            if (!createdRtpmap.equals(rtpmap(applied, format))) {
                throw new InvalidModificationException(where + ": the encoding of format " + format + " changed");
            }
        }
    }

    /// {@return the `a=rtpmap` line of `format`, or `null`}
    private static SdpLine rtpmap(MediaDescription section, String format) {
        for (var line : section.lines()) {
            if (line.isAttribute("rtpmap") && line.attributeValue().orElse("").startsWith(format + " ")) {
                return line;
            }
        }
        return null;
    }

    /// Checks that two line lists are equal once the removable lines and `b=` lines (and, at session level, the
    /// `o=` line) are set aside.
    private static void compareLines(String where, List<SdpLine> created, List<SdpLine> applied, boolean session) {
        var fixedCreated = created.stream().filter(line -> !mungeable(line, session)).toList();
        var fixedApplied = applied.stream().filter(line -> !mungeable(line, session)).toList();
        if (!fixedCreated.equals(fixedApplied)) {
            throw new InvalidModificationException(where + " changed beyond the allowed edits");
        }
    }

    /// {@return whether a line falls under the allowed edits}
    private static boolean mungeable(SdpLine line, boolean session) {
        if (line.type() == 'b' || (session && line.type() == 'o')) {
            return true;
        }
        return line.type() == 'a' && REMOVABLE.contains(line.attributeName());
    }
}
