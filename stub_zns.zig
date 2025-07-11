const std = @import("std");

pub const ZnsConfig = extern struct {
    port: u16,
    enable_recursive: u8,
    enable_caching: u8,
    max_cache_entries: u32,
    default_ttl: u32,
    root_servers: [8][64]u8,
    reserved: [16]u8,
};

pub const ZnsQuery = extern struct {
    domain: [253]u8,
    query_type: u16,
    query_class: u16,
    flags: u16,
    reserved: [8]u8,
};

pub const ZnsResponse = extern struct {
    query: ZnsQuery,
    answers: [16]@import("stub_cns.zig").CnsRecord,
    answer_count: u8,
    response_code: u16,
    authoritative: u8,
    cached: u8,
    ttl: u32,
    reserved: [7]u8,
};

export fn zns_init(config: [*c]const ZnsConfig) ?*opaque {
    _ = config;
    return @ptrFromInt(0x1);
}

export fn zns_destroy(handle: ?*opaque) void {
    _ = handle;
}

export fn zns_start(handle: ?*opaque) c_int {
    _ = handle;
    return 0;
}

export fn zns_query(handle: ?*opaque, query: [*c]const ZnsQuery, response: [*c]ZnsResponse) c_int {
    _ = handle;
    _ = query;
    _ = response;
    return 0;
}