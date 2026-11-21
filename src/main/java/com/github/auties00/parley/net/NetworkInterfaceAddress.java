package com.github.auties00.parley.net;

import java.net.InetAddress;
import java.util.Objects;

/// One address of a local network interface, as a [NetworkStack] reports it for host candidate gathering.
///
/// @param interfaceName the name of the interface, such as `eth0` or `en0`
/// @param address       the address
/// @param prefixLength  the network prefix length in bits, `0..32` for IPv4 and `0..128` for IPv6
/// @param loopback      whether the address is a loopback address
/// @param linkLocal     whether the address is link-local (`169.254.0.0/16` or `fe80::/10`)
/// @param virtual       whether the interface looks like a virtual or tunnel interface (VPN, point-to-point), which
///                      candidate gathering prefers less than a physical one
public record NetworkInterfaceAddress(String interfaceName, InetAddress address, int prefixLength,
                                      boolean loopback, boolean linkLocal, boolean virtual) {
    /// Creates an interface address.
    ///
    /// @param interfaceName the name of the interface
    /// @param address       the address
    /// @param prefixLength  the network prefix length in bits
    /// @param loopback      whether the address is a loopback address
    /// @param linkLocal     whether the address is link-local
    /// @param virtual       whether the interface looks virtual
    /// @throws IllegalArgumentException if `prefixLength` is outside the range of the address family
    public NetworkInterfaceAddress {
        Objects.requireNonNull(interfaceName, "interfaceName cannot be null");
        Objects.requireNonNull(address, "address cannot be null");
        var maximum = address.getAddress().length * 8;
        if (prefixLength < 0 || prefixLength > maximum) {
            throw new IllegalArgumentException("prefix length out of range: " + prefixLength);
        }
    }
}
