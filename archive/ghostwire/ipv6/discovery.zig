//! IPv6 Network Discovery and Auto-configuration
//! Zero-config IPv6 with multicast discovery, router solicitation, and neighbor discovery

const std = @import("std");
const IPv6Address = @import("core.zig").IPv6Address;
const IPv6Subnet = @import("core.zig").IPv6Subnet;
const IPv6Stack = @import("core.zig").IPv6Stack;
const WellKnownAddresses = @import("core.zig").WellKnownAddresses;

pub const DiscoveryConfig = struct {
    enable_router_discovery: bool = true,
    enable_neighbor_discovery: bool = true,
    enable_multicast_discovery: bool = true,
    enable_mdns: bool = true,
    router_solicitation_interval_ms: u32 = 4000,
    neighbor_solicitation_timeout_ms: u32 = 1000,
    multicast_discovery_interval_ms: u32 = 30000,
    max_discovery_attempts: u8 = 3,
};

pub const ICMPv6Type = enum(u8) {
    destination_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,
    echo_request = 128,
    echo_reply = 129,
    multicast_listener_query = 130,
    multicast_listener_report = 131,
    multicast_listener_done = 132,
    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,
    redirect = 137,
};

pub const ICMPv6Message = struct {
    type: ICMPv6Type,
    code: u8,
    checksum: u16,
    data: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, msg_type: ICMPv6Type, code: u8, data: []const u8) !Self {
        return Self{
            .type = msg_type,
            .code = code,
            .checksum = 0, // Will be calculated
            .data = try allocator.dupe(u8, data),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var packet = try allocator.alloc(u8, 4 + self.data.len);
        
        packet[0] = @intFromEnum(self.type);
        packet[1] = self.code;
        std.mem.writeInt(u16, packet[2..4], self.checksum, .big);
        @memcpy(packet[4..], self.data);
        
        return packet;
    }

    pub fn decode(allocator: std.mem.Allocator, packet: []const u8) !Self {
        if (packet.len < 4) return error.InvalidICMPv6Packet;
        
        const msg_type: ICMPv6Type = @enumFromInt(packet[0]);
        const code = packet[1];
        const checksum = std.mem.readInt(u16, packet[2..4], .big);
        const data = try allocator.dupe(u8, packet[4..]);
        
        return Self{
            .type = msg_type,
            .code = code,
            .checksum = checksum,
            .data = data,
            .allocator = allocator,
        };
    }
};

pub const RouterAdvertisement = struct {
    hop_limit: u8,
    managed_flag: bool,
    other_flag: bool,
    router_lifetime: u16,
    reachable_time: u32,
    retrans_timer: u32,
    prefixes: std.ArrayList(PrefixOption),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub const PrefixOption = struct {
        prefix: IPv6Subnet,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .hop_limit = 64,
            .managed_flag = false,
            .other_flag = false,
            .router_lifetime = 0,
            .reachable_time = 0,
            .retrans_timer = 0,
            .prefixes = std.ArrayList(PrefixOption).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.prefixes.deinit();
    }

    pub fn addPrefix(self: *Self, prefix: IPv6Subnet, on_link: bool, autonomous: bool, valid_lifetime: u32, preferred_lifetime: u32) !void {
        try self.prefixes.append(PrefixOption{
            .prefix = prefix,
            .on_link = on_link,
            .autonomous = autonomous,
            .valid_lifetime = valid_lifetime,
            .preferred_lifetime = preferred_lifetime,
        });
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        // Simplified encoding - real implementation would properly format RA options
        var data = std.ArrayList(u8).init(allocator);
        defer data.deinit();

        // Router Advertisement header
        try data.append(self.hop_limit);
        var flags: u8 = 0;
        if (self.managed_flag) flags |= 0x80;
        if (self.other_flag) flags |= 0x40;
        try data.append(flags);
        try data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, self.router_lifetime)));
        try data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.reachable_time)));
        try data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, self.retrans_timer)));

        // Add prefix options (simplified)
        for (self.prefixes.items) |prefix_opt| {
            try data.append(3); // Prefix option type
            try data.append(4); // Option length (32 bytes)
            try data.append(prefix_opt.prefix.prefix_length);
            
            var prefix_flags: u8 = 0;
            if (prefix_opt.on_link) prefix_flags |= 0x80;
            if (prefix_opt.autonomous) prefix_flags |= 0x40;
            try data.append(prefix_flags);
            
            try data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, prefix_opt.valid_lifetime)));
            try data.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, prefix_opt.preferred_lifetime)));
            try data.appendSlice(&[_]u8{0} ** 4); // Reserved
            try data.appendSlice(&prefix_opt.prefix.network.bytes);
        }

        return data.toOwnedSlice();
    }
};

pub const NeighborSolicitation = struct {
    target_address: IPv6Address,
    source_link_layer_address: ?[6]u8,

    const Self = @This();

    pub fn init(target: IPv6Address, source_mac: ?[6]u8) Self {
        return Self{
            .target_address = target,
            .source_link_layer_address = source_mac,
        };
    }

    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var data = try allocator.alloc(u8, 20 + if (self.source_link_layer_address != null) 8 else 0);
        
        // Reserved field
        std.mem.writeInt(u32, data[0..4], 0, .big);
        
        // Target address
        @memcpy(data[4..20], &self.target_address.bytes);
        
        // Source link-layer address option
        if (self.source_link_layer_address) |mac| {
            data[20] = 1; // Option type
            data[21] = 1; // Option length (8 bytes)
            @memcpy(data[22..28], &mac);
        }
        
        return data;
    }
};

pub const MulticastDiscovery = struct {
    config: DiscoveryConfig,
    discovered_nodes: std.HashMap(IPv6Address, NodeInfo, IPv6AddressContext, std.hash_map.default_max_load_percentage),
    multicast_groups: std.ArrayList(IPv6Address),
    allocator: std.mem.Allocator,

    const Self = @This();

    const NodeInfo = struct {
        address: IPv6Address,
        last_seen: i64,
        services: std.ArrayList([]const u8),
        metadata: std.StringHashMap([]const u8),
        
        pub fn init(allocator: std.mem.Allocator, address: IPv6Address) NodeInfo {
            return NodeInfo{
                .address = address,
                .last_seen = std.time.timestamp(),
                .services = std.ArrayList([]const u8).init(allocator),
                .metadata = std.StringHashMap([]const u8).init(allocator),
            };
        }
        
        pub fn deinit(self: *NodeInfo) void {
            for (self.services.items) |service| {
                self.services.allocator.free(service);
            }
            self.services.deinit();
            
            var iter = self.metadata.iterator();
            while (iter.next()) |entry| {
                self.metadata.allocator.free(entry.key_ptr.*);
                self.metadata.allocator.free(entry.value_ptr.*);
            }
            self.metadata.deinit();
        }
    };

    const IPv6AddressContext = @import("core.zig").IPv6Stack.IPv6AddressContext;

    pub fn init(allocator: std.mem.Allocator, config: DiscoveryConfig) Self {
        return Self{
            .config = config,
            .discovered_nodes = std.HashMap(IPv6Address, NodeInfo, IPv6AddressContext, std.hash_map.default_max_load_percentage).init(allocator),
            .multicast_groups = std.ArrayList(IPv6Address).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.discovered_nodes.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.discovered_nodes.deinit();
        self.multicast_groups.deinit();
    }

    pub fn joinMulticastGroup(self: *Self, group: IPv6Address) !void {
        try self.multicast_groups.append(group);
    }

    pub fn leaveMulticastGroup(self: *Self, group: IPv6Address) void {
        for (self.multicast_groups.items, 0..) |existing_group, i| {
            if (std.mem.eql(u8, &existing_group.bytes, &group.bytes)) {
                _ = self.multicast_groups.swapRemove(i);
                break;
            }
        }
    }

    pub fn discoverNodes(self: *Self, interface_name: []const u8) ![]IPv6Address {
        _ = interface_name;
        
        // Send multicast discovery request
        _ = try IPv6Address.fromString("ff02::1"); // All nodes
        
        // In a real implementation, this would send ICMPv6 or custom discovery packets
        // and listen for responses
        
        var discovered = std.ArrayList(IPv6Address).init(self.allocator);
        defer discovered.deinit();
        
        // Return discovered node addresses
        var iter = self.discovered_nodes.iterator();
        while (iter.next()) |entry| {
            try discovered.append(entry.key_ptr.*);
        }
        
        return discovered.toOwnedSlice();
    }

    pub fn announcePresence(self: *Self, services: []const []const u8, metadata: std.StringHashMap([]const u8)) !void {
        _ = self;
        _ = services;
        _ = metadata;
        
        // Send multicast announcement with service information
        // Implementation would construct and send announcement packet
    }

    pub fn processDiscoveryMessage(self: *Self, source: IPv6Address, message: []const u8) !void {
        // Process incoming discovery message and update node information
        var node_info = self.discovered_nodes.get(source) orelse blk: {
            const new_info = NodeInfo.init(self.allocator, source);
            try self.discovered_nodes.put(source, new_info);
            break :blk self.discovered_nodes.getPtr(source).?;
        };
        
        node_info.last_seen = std.time.timestamp();
        
        // Parse message for service and metadata information
        // Simplified - real implementation would parse structured discovery protocol
        if (std.mem.indexOf(u8, message, "service:")) |service_start| {
            const service_line_start = service_start + "service:".len;
            const service_line_end = std.mem.indexOfScalarPos(u8, message, service_line_start, '\n') orelse message.len;
            const service_name = std.mem.trim(u8, message[service_line_start..service_line_end], " \t");
            
            const owned_service = try self.allocator.dupe(u8, service_name);
            try node_info.services.append(owned_service);
        }
    }

    pub fn getDiscoveredNodes(self: *const Self) []IPv6Address {
        var nodes = std.ArrayList(IPv6Address).init(self.allocator);
        defer nodes.deinit();
        
        var iter = self.discovered_nodes.iterator();
        while (iter.next()) |entry| {
            nodes.append(entry.key_ptr.*) catch continue;
        }
        
        return nodes.toOwnedSlice() catch &[_]IPv6Address{};
    }

    pub fn cleanupStaleNodes(self: *Self, timeout_seconds: i64) void {
        const now = std.time.timestamp();
        var to_remove = std.ArrayList(IPv6Address).init(self.allocator);
        defer to_remove.deinit();
        
        var iter = self.discovered_nodes.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.last_seen > timeout_seconds) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (to_remove.items) |addr| {
            if (self.discovered_nodes.fetchRemove(addr)) |removed| {
                removed.value.deinit();
            }
        }
    }
};

pub const IPv6Discovery = struct {
    config: DiscoveryConfig,
    stack: *IPv6Stack,
    multicast_discovery: MulticastDiscovery,
    router_cache: std.ArrayList(RouterInfo),
    allocator: std.mem.Allocator,

    const Self = @This();

    const RouterInfo = struct {
        address: IPv6Address,
        last_advertisement: i64,
        lifetime: u16,
        prefixes: std.ArrayList(RouterAdvertisement.PrefixOption),
        
        pub fn init(allocator: std.mem.Allocator, address: IPv6Address) RouterInfo {
            return RouterInfo{
                .address = address,
                .last_advertisement = std.time.timestamp(),
                .lifetime = 0,
                .prefixes = std.ArrayList(RouterAdvertisement.PrefixOption).init(allocator),
            };
        }
        
        pub fn deinit(self: *RouterInfo) void {
            self.prefixes.deinit();
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: DiscoveryConfig, stack: *IPv6Stack) Self {
        return Self{
            .config = config,
            .stack = stack,
            .multicast_discovery = MulticastDiscovery.init(allocator, config),
            .router_cache = std.ArrayList(RouterInfo).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.multicast_discovery.deinit();
        for (self.router_cache.items) |*router| {
            router.deinit();
        }
        self.router_cache.deinit();
    }

    pub fn startDiscovery(self: *Self, interface_name: []const u8) !void {
        if (self.config.enable_router_discovery) {
            try self.sendRouterSolicitation(interface_name);
        }
        
        if (self.config.enable_multicast_discovery) {
            try self.multicast_discovery.joinMulticastGroup(WellKnownAddresses.ALL_NODES_LINK_LOCAL);
            _ = try self.multicast_discovery.discoverNodes(interface_name);
        }
    }

    pub fn stopDiscovery(self: *Self) void {
        self.multicast_discovery.leaveMulticastGroup(WellKnownAddresses.ALL_NODES_LINK_LOCAL);
    }

    fn sendRouterSolicitation(self: *Self, interface_name: []const u8) !void {
        _ = interface_name;
        
        // Create and send router solicitation message
        const rs_data = &[_]u8{0} ** 4; // Reserved field
        var rs_message = try ICMPv6Message.init(
            self.allocator,
            .router_solicitation,
            0,
            rs_data
        );
        defer rs_message.deinit();
        
        // In real implementation, would send to all-routers multicast address
        // and wait for router advertisements
    }

    pub fn processRouterAdvertisement(self: *Self, source: IPv6Address, ra_data: []const u8) !void {
        _ = ra_data;
        
        // Process router advertisement and update routing table
        const router_info = RouterInfo.init(self.allocator, source);
        try self.router_cache.append(router_info);
        
        // Parse RA options and configure addresses/routes
        // Implementation would parse real RA packet format
    }

    pub fn performNeighborDiscovery(self: *Self, target: IPv6Address, interface_name: []const u8) !?[6]u8 {
        _ = interface_name;
        
        // Send neighbor solicitation
        const ns = NeighborSolicitation.init(target, null);
        const ns_data = try ns.encode(self.allocator);
        defer self.allocator.free(ns_data);
        
        var ns_message = try ICMPv6Message.init(
            self.allocator,
            .neighbor_solicitation,
            0,
            ns_data
        );
        defer ns_message.deinit();
        
        // In real implementation, would send NS and wait for NA response
        // Return MAC address from neighbor advertisement
        return null;
    }

    pub fn enableZeroConfig(self: *Self, interface_name: []const u8) !void {
        try self.stack.enableInterface(interface_name);
        try self.startDiscovery(interface_name);
        
        // Start periodic discovery
        // In real implementation, would run discovery in background thread
    }

    pub fn getAvailableRouters(self: *const Self) []IPv6Address {
        var routers = std.ArrayList(IPv6Address).init(self.allocator);
        defer routers.deinit();
        
        for (self.router_cache.items) |router| {
            routers.append(router.address) catch continue;
        }
        
        return routers.toOwnedSlice() catch &[_]IPv6Address{};
    }
};

test "ICMPv6 message encoding/decoding" {
    const allocator = std.testing.allocator;
    
    const data = "test data";
    var message = try ICMPv6Message.init(allocator, .echo_request, 0, data);
    defer message.deinit();
    
    const encoded = try message.encode(allocator);
    defer allocator.free(encoded);
    
    var decoded = try ICMPv6Message.decode(allocator, encoded);
    defer decoded.deinit();
    
    try std.testing.expect(decoded.type == .echo_request);
    try std.testing.expect(std.mem.eql(u8, decoded.data, data));
}

test "multicast discovery" {
    const allocator = std.testing.allocator;
    
    const config = DiscoveryConfig{};
    var discovery = MulticastDiscovery.init(allocator, config);
    defer discovery.deinit();
    
    const group = try IPv6Address.fromString("ff02::1");
    try discovery.joinMulticastGroup(group);
    
    try std.testing.expect(discovery.multicast_groups.items.len == 1);
}