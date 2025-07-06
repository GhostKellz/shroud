//! Core IPv6 networking implementation for Ghostwire
//! Native IPv6 support with dual-stack fallback and zero-configuration

const std = @import("std");

pub const IPv6Address = struct {
    bytes: [16]u8,

    const Self = @This();

    pub fn init(bytes: [16]u8) Self {
        return Self{ .bytes = bytes };
    }

    pub fn fromString(addr_str: []const u8) !Self {
        const address = std.net.Address.parseIp6(addr_str, 0) catch return error.InvalidAddress;
        return Self{ .bytes = address.in6.sa.addr };
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const addr = std.net.Address.initIp6(self.bytes, 0);
        return std.fmt.allocPrint(allocator, "{}", .{addr});
    }

    pub fn isLoopback(self: Self) bool {
        return std.mem.eql(u8, &self.bytes, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    }

    pub fn isLinkLocal(self: Self) bool {
        return self.bytes[0] == 0xfe and (self.bytes[1] & 0xc0) == 0x80;
    }

    pub fn isUniqueLocal(self: Self) bool {
        return (self.bytes[0] & 0xfe) == 0xfc;
    }

    pub fn isMulticast(self: Self) bool {
        return self.bytes[0] == 0xff;
    }

    pub fn isGlobalUnicast(self: Self) bool {
        return !self.isLoopback() and !self.isLinkLocal() and !self.isUniqueLocal() and !self.isMulticast();
    }

    pub fn getScope(self: Self) AddressScope {
        if (self.isLoopback()) return .host;
        if (self.isLinkLocal()) return .link;
        if (self.isUniqueLocal()) return .site;
        if (self.isMulticast()) {
            return switch (self.bytes[1] & 0x0f) {
                1 => .interface,
                2 => .link,
                5 => .site,
                8 => .organization,
                14 => .global,
                else => .unknown,
            };
        }
        return .global;
    }

    pub fn inSubnet(self: Self, subnet: IPv6Subnet) bool {
        const prefix_bytes = (subnet.prefix_length + 7) / 8;
        const remaining_bits = subnet.prefix_length % 8;

        // Check full bytes
        for (0..prefix_bytes - 1) |i| {
            if (self.bytes[i] != subnet.network.bytes[i]) return false;
        }

        // Check remaining bits in the last byte
        if (remaining_bits > 0 and prefix_bytes > 0) {
            const mask = ~(@as(u8, 0xFF) >> @intCast(remaining_bits));
            const last_byte_index = prefix_bytes - 1;
            if ((self.bytes[last_byte_index] & mask) != (subnet.network.bytes[last_byte_index] & mask)) {
                return false;
            }
        }

        return true;
    }
};

pub const AddressScope = enum {
    interface,  // Node-local (::1)
    link,       // Link-local (fe80::/10)
    site,       // Site-local/Unique local (fc00::/7)
    organization, // Organization-local
    global,     // Global unicast
    host,       // Host loopback
    unknown,
};

pub const IPv6Subnet = struct {
    network: IPv6Address,
    prefix_length: u8,

    const Self = @This();

    pub fn init(network: IPv6Address, prefix_length: u8) Self {
        return Self{
            .network = network,
            .prefix_length = prefix_length,
        };
    }

    pub fn fromString(subnet_str: []const u8) !Self {
        const slash_pos = std.mem.indexOf(u8, subnet_str, "/") orelse return error.InvalidSubnet;
        
        const network_str = subnet_str[0..slash_pos];
        const prefix_str = subnet_str[slash_pos + 1..];
        
        const network = try IPv6Address.fromString(network_str);
        const prefix_length = try std.fmt.parseInt(u8, prefix_str, 10);
        
        if (prefix_length > 128) return error.InvalidPrefixLength;
        
        return Self.init(network, prefix_length);
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const network_str = try self.network.toString(allocator);
        defer allocator.free(network_str);
        return std.fmt.allocPrint(allocator, "{s}/{d}", .{ network_str, self.prefix_length });
    }

    pub fn contains(self: Self, address: IPv6Address) bool {
        return address.inSubnet(self);
    }
};

pub const IPv6Interface = struct {
    name: []const u8,
    addresses: std.ArrayList(IPv6Address),
    mtu: u32,
    up: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Self {
        return Self{
            .name = name,
            .addresses = std.ArrayList(IPv6Address).init(allocator),
            .mtu = 1500,
            .up = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.addresses.deinit();
    }

    pub fn addAddress(self: *Self, address: IPv6Address) !void {
        try self.addresses.append(address);
    }

    pub fn hasGlobalAddress(self: *const Self) bool {
        for (self.addresses.items) |addr| {
            if (addr.isGlobalUnicast()) return true;
        }
        return false;
    }

    pub fn getLinkLocalAddress(self: *const Self) ?IPv6Address {
        for (self.addresses.items) |addr| {
            if (addr.isLinkLocal()) return addr;
        }
        return null;
    }

    pub fn getGlobalAddresses(self: *const Self, allocator: std.mem.Allocator) ![]IPv6Address {
        var global_addrs = std.ArrayList(IPv6Address).init(allocator);
        defer global_addrs.deinit();

        for (self.addresses.items) |addr| {
            if (addr.isGlobalUnicast()) {
                try global_addrs.append(addr);
            }
        }

        return global_addrs.toOwnedSlice();
    }
};

pub const IPv6Config = struct {
    enable_dual_stack: bool = true,
    prefer_ipv6: bool = true,
    enable_privacy_extensions: bool = true,
    enable_zero_config: bool = true,
    router_solicitation_interval_ms: u32 = 4000,
    max_router_solicitations: u8 = 3,
    neighbor_cache_timeout_ms: u32 = 30000,
};

pub const IPv6Stack = struct {
    config: IPv6Config,
    interfaces: std.StringHashMap(*IPv6Interface),
    neighbor_cache: std.HashMap(IPv6Address, NeighborEntry, IPv6AddressContext, std.hash_map.default_max_load_percentage),
    route_table: std.ArrayList(RouteEntry),
    allocator: std.mem.Allocator,

    const Self = @This();

    const NeighborEntry = struct {
        mac_address: [6]u8,
        state: NeighborState,
        last_updated: i64,
    };

    const NeighborState = enum {
        incomplete,
        reachable,
        stale,
        delay,
        probe,
    };

    const RouteEntry = struct {
        destination: IPv6Subnet,
        gateway: ?IPv6Address,
        interface: []const u8,
        metric: u32,
    };

    const IPv6AddressContext = struct {
        pub fn hash(self: @This(), addr: IPv6Address) u64 {
            _ = self;
            return std.hash.Wyhash.hash(0, &addr.bytes);
        }

        pub fn eql(self: @This(), a: IPv6Address, b: IPv6Address) bool {
            _ = self;
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: IPv6Config) Self {
        return Self{
            .config = config,
            .interfaces = std.StringHashMap(*IPv6Interface).init(allocator),
            .neighbor_cache = std.HashMap(IPv6Address, NeighborEntry, IPv6AddressContext, std.hash_map.default_max_load_percentage).init(allocator),
            .route_table = std.ArrayList(RouteEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var interface_iter = self.interfaces.iterator();
        while (interface_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.interfaces.deinit();
        self.neighbor_cache.deinit();
        self.route_table.deinit();
    }

    pub fn addInterface(self: *Self, name: []const u8) !*IPv6Interface {
        const interface = try self.allocator.create(IPv6Interface);
        interface.* = IPv6Interface.init(self.allocator, name);
        try self.interfaces.put(name, interface);
        return interface;
    }

    pub fn getInterface(self: *Self, name: []const u8) ?*IPv6Interface {
        return self.interfaces.get(name);
    }

    pub fn addRoute(self: *Self, destination: IPv6Subnet, gateway: ?IPv6Address, interface_name: []const u8, metric: u32) !void {
        const route = RouteEntry{
            .destination = destination,
            .gateway = gateway,
            .interface = interface_name,
            .metric = metric,
        };
        try self.route_table.append(route);
    }

    pub fn findRoute(self: *Self, destination: IPv6Address) ?RouteEntry {
        var best_route: ?RouteEntry = null;
        var longest_prefix: u8 = 0;

        for (self.route_table.items) |route| {
            if (route.destination.contains(destination) and route.destination.prefix_length >= longest_prefix) {
                longest_prefix = route.destination.prefix_length;
                best_route = route;
            }
        }

        return best_route;
    }

    pub fn enableInterface(self: *Self, name: []const u8) !void {
        if (self.interfaces.get(name)) |interface| {
            interface.up = true;
            
            // Generate link-local address if zero-config is enabled
            if (self.config.enable_zero_config) {
                try self.generateLinkLocalAddress(interface);
            }
        }
    }

    pub fn disableInterface(self: *Self, name: []const u8) !void {
        if (self.interfaces.get(name)) |interface| {
            interface.up = false;
        }
    }

    fn generateLinkLocalAddress(self: *Self, interface: *IPv6Interface) !void {
        _ = self;
        
        // Generate link-local address (fe80::/64 + interface identifier)
        var link_local_bytes = [_]u8{0xfe, 0x80} ++ [_]u8{0} ** 6;
        
        // Simple interface identifier (in practice, use MAC address or random)
        const interface_id = std.hash.Wyhash.hash(0, interface.name);
        std.mem.writeInt(u64, link_local_bytes[8..16], interface_id, .big);
        
        const link_local_addr = IPv6Address.init(link_local_bytes);
        try interface.addAddress(link_local_addr);
    }

    pub fn isIPv6Preferred(self: *Self, destination: IPv6Address) bool {
        _ = destination;
        return self.config.prefer_ipv6;
    }

    pub fn selectSourceAddress(self: *Self, destination: IPv6Address, interface_name: ?[]const u8) ?IPv6Address {
        // Simplified source address selection (RFC 6724)
        
        if (interface_name) |iface_name| {
            if (self.interfaces.get(iface_name)) |interface| {
                // Prefer same scope as destination
                const dest_scope = destination.getScope();
                
                for (interface.addresses.items) |addr| {
                    if (addr.getScope() == dest_scope) {
                        return addr;
                    }
                }
                
                // Fallback to any global address
                for (interface.addresses.items) |addr| {
                    if (addr.isGlobalUnicast()) {
                        return addr;
                    }
                }
                
                // Fallback to link-local
                return interface.getLinkLocalAddress();
            }
        } else {
            // Select from any interface
            var interface_iter = self.interfaces.iterator();
            while (interface_iter.next()) |entry| {
                const interface = entry.value_ptr.*;
                if (!interface.up) continue;
                
                for (interface.addresses.items) |addr| {
                    if (addr.getScope() == destination.getScope()) {
                        return addr;
                    }
                }
            }
        }
        
        return null;
    }

    pub fn getDualStackPreference(self: *Self, ipv4_available: bool, ipv6_available: bool) TransportPreference {
        if (!self.config.enable_dual_stack) {
            return if (ipv6_available) .ipv6_only else .ipv4_only;
        }
        
        if (self.config.prefer_ipv6 and ipv6_available) {
            return if (ipv4_available) .ipv6_preferred else .ipv6_only;
        } else if (ipv4_available) {
            return if (ipv6_available) .ipv4_preferred else .ipv4_only;
        } else if (ipv6_available) {
            return .ipv6_only;
        }
        
        return .none_available;
    }
};

pub const TransportPreference = enum {
    ipv4_only,
    ipv6_only,
    ipv4_preferred,
    ipv6_preferred,
    none_available,
};

// Well-known IPv6 addresses and prefixes
pub const WellKnownAddresses = struct {
    pub const LOOPBACK = IPv6Address.init([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    pub const UNSPECIFIED = IPv6Address.init([_]u8{0} ** 16);
    
    // Multicast addresses
    pub const ALL_NODES_LINK_LOCAL = IPv6Address.init([_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    pub const ALL_ROUTERS_LINK_LOCAL = IPv6Address.init([_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 });
    pub const ALL_DHCP_SERVERS = IPv6Address.init([_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 });
    
    // Common prefixes
    pub const LINK_LOCAL_PREFIX = IPv6Subnet.init(
        IPv6Address.init([_]u8{ 0xfe, 0x80 } ++ [_]u8{0} ** 14),
        10
    );
    pub const UNIQUE_LOCAL_PREFIX = IPv6Subnet.init(
        IPv6Address.init([_]u8{ 0xfc, 0x00 } ++ [_]u8{0} ** 14),
        7
    );
    pub const MULTICAST_PREFIX = IPv6Subnet.init(
        IPv6Address.init([_]u8{ 0xff, 0x00 } ++ [_]u8{0} ** 14),
        8
    );
};

test "IPv6 address parsing and classification" {
    const addr_str = "2001:db8::1";
    const addr = try IPv6Address.fromString(addr_str);
    
    try std.testing.expect(addr.isGlobalUnicast());
    try std.testing.expect(!addr.isLinkLocal());
    try std.testing.expect(!addr.isLoopback());
    try std.testing.expect(addr.getScope() == .global);
}

test "IPv6 subnet operations" {
    const subnet = try IPv6Subnet.fromString("2001:db8::/32");
    
    const addr_in = try IPv6Address.fromString("2001:db8::1");
    const addr_out = try IPv6Address.fromString("2001:db9::1");
    
    try std.testing.expect(subnet.contains(addr_in));
    try std.testing.expect(!subnet.contains(addr_out));
}

test "IPv6 interface management" {
    const allocator = std.testing.allocator;
    
    const config = IPv6Config{};
    var stack = IPv6Stack.init(allocator, config);
    defer stack.deinit();
    
    const interface = try stack.addInterface("eth0");
    const addr = try IPv6Address.fromString("2001:db8::1");
    try interface.addAddress(addr);
    
    try std.testing.expect(interface.hasGlobalAddress());
}