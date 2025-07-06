const std = @import("std");
const zquic = @import("zquic");
const types = @import("../resolver/types.zig");

/// QUIC-based DNS resolver for DNS-over-QUIC support
pub const QuicDnsClient = struct {
    allocator: std.mem.Allocator,
    zquic_client: ?zquic.ZQuic,
    
    pub fn init(allocator: std.mem.Allocator) QuicDnsClient {
        return QuicDnsClient{
            .allocator = allocator,
            .zquic_client = null,
        };
    }
    
    pub fn deinit(self: *QuicDnsClient) void {
        if (self.zquic_client) |*client| {
            client.deinit();
        }
    }
    
    /// Connect to QUIC endpoint
    pub fn connect(self: *QuicDnsClient, endpoint: []const u8) !void {
        // Initialize ZQUIC client
        const config = zquic.ZQuicConfig{
            .port = 853, // DNS-over-QUIC standard port
            .max_connections = 10,
            .alpn = "doq", // DNS-over-QUIC ALPN
        };
        
        self.zquic_client = try zquic.ZQuic.new(config);
        
        // Connect to endpoint
        try self.zquic_client.?.connect(endpoint);
    }
    
    /// Make DNS query over QUIC
    pub fn dnsQuery(
        self: *QuicDnsClient, 
        domain: []const u8, 
        record_type: []const u8
    ) !DnsResponse {
        if (self.zquic_client == null) {
            return error.NotConnected;
        }
        
        // Use ZQUIC FFI DNS query function
        const response_data = try self.zquic_client.?.dns_query(domain, record_type);
        defer self.allocator.free(response_data);
        
        return self.parseDnsResponse(domain, response_data);
    }
    
    /// Make gRPC call over QUIC (for GhostBridge integration)
    pub fn grpcCall(
        self: *QuicDnsClient,
        service_method: []const u8,
        request_data: []const u8,
    ) ![]u8 {
        if (self.zquic_client == null) {
            return error.NotConnected;
        }
        
        // Use ZQUIC FFI gRPC call function
        return self.zquic_client.?.grpc_call(service_method, request_data);
    }
    
    /// Parse DNS response data
    fn parseDnsResponse(self: *QuicDnsClient, domain: []const u8, data: []const u8) !DnsResponse {
        // Parse JSON response from DNS-over-QUIC
        var parser = std.json.Parser.init(self.allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(data);
        defer tree.deinit();
        
        const root = tree.root;
        
        if (root.Object.get("Status")) |status| {
            if (status.Integer != 0) {
                return error.DnsQueryFailed;
            }
        }
        
        var records = std.ArrayList(DnsRecord).init(self.allocator);
        defer records.deinit();
        
        if (root.Object.get("Answer")) |answer_array| {
            for (answer_array.Array.items) |answer| {
                const record_type = answer.Object.get("type").?.Integer;
                const record_data = answer.Object.get("data").?.String;
                const ttl = answer.Object.get("TTL").?.Integer;
                
                const record = DnsRecord{
                    .name = try self.allocator.dupe(u8, domain),
                    .record_type = try self.mapRecordType(@intCast(record_type)),
                    .value = try self.allocator.dupe(u8, record_data),
                    .ttl = @intCast(ttl),
                };
                
                try records.append(record);
            }
        }
        
        return DnsResponse{
            .domain = try self.allocator.dupe(u8, domain),
            .records = try records.toOwnedSlice(),
            .status = 0,
        };
    }
    
    /// Map numeric DNS record type to enum
    fn mapRecordType(self: *QuicDnsClient, record_type: u16) !types.DNSRecordType {
        _ = self;
        return switch (record_type) {
            1 => .A,
            28 => .AAAA,
            16 => .TXT,
            5 => .CNAME,
            15 => .MX,
            33 => .SRV,
            else => .TXT, // Default fallback
        };
    }
};

/// DNS response structure
pub const DnsResponse = struct {
    domain: []const u8,
    records: []DnsRecord,
    status: u8,
    
    pub fn deinit(self: *DnsResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        for (self.records) |*record| {
            record.deinit(allocator);
        }
        allocator.free(self.records);
    }
};

/// Individual DNS record
pub const DnsRecord = struct {
    name: []const u8,
    record_type: types.DNSRecordType,
    value: []const u8,
    ttl: u32,
    
    pub fn deinit(self: *DnsRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

/// gRPC-over-QUIC client for GhostBridge integration
pub const QuicGrpcClient = struct {
    quic_client: QuicDnsClient,
    endpoint: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8) !QuicGrpcClient {
        var client = QuicDnsClient.init(allocator);
        try client.connect(endpoint);
        
        return QuicGrpcClient{
            .quic_client = client,
            .endpoint = endpoint,
        };
    }
    
    pub fn deinit(self: *QuicGrpcClient) void {
        self.quic_client.deinit();
    }
    
    /// Make gRPC call to ZNS service
    pub fn resolveGhostDomain(self: *QuicGrpcClient, domain: []const u8) !types.CryptoAddress {
        // Create gRPC request
        const request = try std.fmt.allocPrint(
            self.quic_client.allocator,
            "{{\"domain\": \"{s}\", \"record_types\": [\"A\"], \"include_metadata\": true}}",
            .{domain}
        );
        defer self.quic_client.allocator.free(request);
        
        // Make gRPC call over QUIC
        const response = try self.quic_client.grpcCall(
            "ghost.zns.ZNSService/ResolveDomain",
            request
        );
        defer self.quic_client.allocator.free(response);
        
        // Parse gRPC response
        return self.parseGrpcResponse(domain, response);
    }
    
    /// Parse gRPC response from GhostBridge
    fn parseGrpcResponse(self: *QuicGrpcClient, domain: []const u8, data: []const u8) !types.CryptoAddress {
        var parser = std.json.Parser.init(self.quic_client.allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(data);
        defer tree.deinit();
        
        const root = tree.root;
        
        // Extract address from response
        const records = root.Object.get("records").?.Array;
        if (records.items.len == 0) {
            return error.DomainNotFound;
        }
        
        const first_record = records.items[0];
        const address = first_record.Object.get("value").?.String;
        
        return types.CryptoAddress.init(
            self.quic_client.allocator,
            domain,
            .ghostchain,
            address
        );
    }
    
    /// Register domain via gRPC-over-QUIC
    pub fn registerGhostDomain(
        self: *QuicGrpcClient,
        domain: []const u8,
        owner_pubkey: [32]u8,
        records: []const types.DNSRecord,
        signature: [64]u8,
    ) !RegisterResult {
        // Create registration request
        const request = try self.buildRegisterRequest(domain, owner_pubkey, records, signature);
        defer self.quic_client.allocator.free(request);
        
        // Make gRPC call
        const response = try self.quic_client.grpcCall(
            "ghost.zns.ZNSService/RegisterDomain",
            request
        );
        defer self.quic_client.allocator.free(response);
        
        return self.parseRegisterResponse(response);
    }
    
    /// Build domain registration request
    fn buildRegisterRequest(
        self: *QuicGrpcClient,
        domain: []const u8,
        owner_pubkey: [32]u8,
        records: []const types.DNSRecord,
        signature: [64]u8,
    ) ![]u8 {
        _ = records; // TODO: Implement records serialization
        
        // Convert pubkey and signature to hex
        var pubkey_hex: [64]u8 = undefined;
        var sig_hex: [128]u8 = undefined;
        
        _ = try std.fmt.bufPrint(&pubkey_hex, "{}", .{std.fmt.fmtSliceHexLower(&owner_pubkey)});
        _ = try std.fmt.bufPrint(&sig_hex, "{}", .{std.fmt.fmtSliceHexLower(&signature)});
        
        return std.fmt.allocPrint(
            self.quic_client.allocator,
            "{{\"domain\": \"{s}\", \"owner_pubkey\": \"{s}\", \"signature\": \"{s}\", \"records\": []}}",
            .{ domain, pubkey_hex, sig_hex }
        );
    }
    
    /// Parse registration response
    fn parseRegisterResponse(self: *QuicGrpcClient, data: []const u8) !RegisterResult {
        var parser = std.json.Parser.init(self.quic_client.allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(data);
        defer tree.deinit();
        
        const root = tree.root;
        const success = root.Object.get("success").?.Bool;
        
        if (success) {
            const tx_hash = root.Object.get("transaction_hash").?.String;
            return RegisterResult{
                .success = true,
                .transaction_hash = try self.quic_client.allocator.dupe(u8, tx_hash),
                .error_message = null,
            };
        } else {
            const error_msg = root.Object.get("error").?.String;
            return RegisterResult{
                .success = false,
                .transaction_hash = null,
                .error_message = try self.quic_client.allocator.dupe(u8, error_msg),
            };
        }
    }
};

/// Domain registration result
pub const RegisterResult = struct {
    success: bool,
    transaction_hash: ?[]const u8,
    error_message: ?[]const u8,
    
    pub fn deinit(self: *RegisterResult, allocator: std.mem.Allocator) void {
        if (self.transaction_hash) |hash| {
            allocator.free(hash);
        }
        if (self.error_message) |msg| {
            allocator.free(msg);
        }
    }
};
