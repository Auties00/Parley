package com.github.auties00.parley.ice;

import com.github.auties00.parley.net.NetworkInterfaceAddress;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;

/// Chooses and orders the local addresses host candidates are gathered on.
///
/// Loopback and link-local addresses are left out unless allowed (loopback is used anyway when nothing else is
/// left, so two agents on one machine still connect), as are virtual interfaces when excluded. The rest is ordered
/// as RFC 8421 section 4 recommends for dual-stack hosts: physical interfaces before virtual ones, then IPv6 and
/// IPv4 interleaved with IPv6 first, so the checklist alternates families instead of exhausting one before trying
/// the other. The local preference of an address falls with its rank.
///
/// @spec https://www.rfc-editor.org/rfc/rfc8421.html RFC 8421: Guidelines for Multihomed and IPv4/IPv6 Dual-Stack Interactive Connectivity Establishment (ICE)
final class HostAddresses {
    /// The step between the local preferences of two consecutive addresses.
    private static final int PREFERENCE_STEP = 256;

    /// Not instantiated.
    private HostAddresses() {
    }

    /// One chosen address and its local preference.
    ///
    /// @param address         the interface address
    /// @param localPreference the local preference of its UDP candidates, `0..65535`
    /// @param rank            the rank, `0` for the most preferred
    record Ranked(NetworkInterfaceAddress address, int localPreference, int rank) {
    }

    /// {@return the addresses to gather on, best first}
    ///
    /// @param all       every interface address of the stack
    /// @param loopback  whether loopback addresses may be used when others exist
    /// @param linkLocal whether link-local addresses may be used
    /// @param virtual   whether virtual interfaces may be used
    /// @param filter    an application filter every address must pass
    static List<Ranked> choose(List<NetworkInterfaceAddress> all, boolean loopback, boolean linkLocal, boolean virtual,
                               Predicate<NetworkInterfaceAddress> filter) {
        var usable = new ArrayList<NetworkInterfaceAddress>();
        var loopbacks = new ArrayList<NetworkInterfaceAddress>();
        for (var address : all) {
            if (address.address().isAnyLocalAddress() || address.address().isMulticastAddress() || !filter.test(address)) {
                continue;
            }
            if (address.loopback()) {
                loopbacks.add(address);
                continue;
            }
            if (address.linkLocal() && !linkLocal) {
                continue;
            }
            if (address.virtual() && !virtual) {
                continue;
            }
            if (isIpv4Mapped(address)) {
                continue;
            }
            usable.add(address);
        }
        if (loopback || usable.isEmpty()) {
            usable.addAll(loopbacks);
        }
        var byQuality = Comparator.comparing(NetworkInterfaceAddress::loopback)
                .thenComparing(NetworkInterfaceAddress::virtual)
                .thenComparing(NetworkInterfaceAddress::linkLocal);
        var ipv6 = usable.stream().filter(address -> address.address() instanceof Inet6Address).sorted(byQuality).toList();
        var ipv4 = usable.stream().filter(address -> address.address() instanceof Inet4Address).sorted(byQuality).toList();
        var ordered = new ArrayList<NetworkInterfaceAddress>(usable.size());
        for (var i = 0; i < Math.max(ipv6.size(), ipv4.size()); i++) {
            if (i < ipv6.size()) {
                ordered.add(ipv6.get(i));
            }
            if (i < ipv4.size()) {
                ordered.add(ipv4.get(i));
            }
        }
        var result = new ArrayList<Ranked>(ordered.size());
        for (var rank = 0; rank < ordered.size(); rank++) {
            result.add(new Ranked(ordered.get(rank), Math.max(0, 65535 - rank * PREFERENCE_STEP), rank));
        }
        return List.copyOf(result);
    }

    /// {@return whether an IPv6 address is an IPv4-mapped address, which is not a separate interface}
    private static boolean isIpv4Mapped(NetworkInterfaceAddress address) {
        var bytes = address.address().getAddress();
        if (bytes.length != 16) {
            return false;
        }
        for (var i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }
}
